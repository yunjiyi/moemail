import { createDb } from "@/lib/db"
import { emails, messages } from "@/lib/schema"
import { eq, and, lt, or, sql, ne, isNull } from "drizzle-orm"
import { encodeCursor, decodeCursor } from "@/lib/cursor"
import { getUserId } from "@/lib/apiKey"
import { checkBasicSendPermission } from "@/lib/send-permissions"

export const runtime = "edge"

const allowedOrigins = [
  "https://toolxp.com",
  "https://www.toolxp.com"
]

function isAllowed(request: Request) {
  const origin = request.headers.get("origin") || ""
  const referer = request.headers.get("referer") || ""
  return (
    allowedOrigins.includes(origin) ||
    allowedOrigins.some(url => referer.startsWith(url))
  )
}

export async function OPTIONS(request: Request) {
  const origin = request.headers.get("origin") || ""
  if (!isAllowed(request)) {
    return new Response("非法来源", { status: 403 })
  }
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
    }
  })
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const origin = request.headers.get("origin") || ""
  if (!isAllowed(request)) {
    return new Response(JSON.stringify({ error: "非法来源，禁止访问 API" }), {
      status: 403,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
      }
    })
  }

  const userId = await getUserId()
  try {
    const db = createDb()
    const { id } = await params
    const email = await db.query.emails.findFirst({
      where: and(
        eq(emails.id, id),
        eq(emails.userId, userId!)
      )
    })

    if (!email) {
      return new Response(JSON.stringify({ error: "邮箱不存在或无权限删除" }), {
        status: 403,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
        }
      })
    }

    await db.delete(messages).where(eq(messages.emailId, id))
    await db.delete(emails).where(eq(emails.id, id))

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
      }
    })
  } catch (error) {
    console.error("Failed to delete email:", error)
    return new Response(JSON.stringify({ error: "删除邮箱失败" }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
      }
    })
  }
}

const PAGE_SIZE = 20

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const origin = request.headers.get("origin") || ""
  if (!isAllowed(request)) {
    return new Response(JSON.stringify({ error: "非法来源，禁止访问 API" }), {
      status: 403,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
      }
    })
  }

  const { searchParams } = new URL(request.url)
  const cursorStr = searchParams.get("cursor")
  const messageType = searchParams.get("type")

  try {
    const db = createDb()
    const { id } = await params
    const userId = await getUserId()

    if (messageType === "sent") {
      const permissionResult = await checkBasicSendPermission(userId!)
      if (!permissionResult.canSend) {
        return new Response(JSON.stringify({
          error: permissionResult.error || "您没有查看发送邮件的权限"
        }), {
          status: 403,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
          }
        })
      }
    }

    const email = await db.query.emails.findFirst({
      where: and(
        eq(emails.id, id),
        eq(emails.userId, userId!)
      )
    })

    if (!email) {
      return new Response(JSON.stringify({ error: "无权限查看" }), {
        status: 403,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
        }
      })
    }

    const baseConditions = and(
      eq(messages.emailId, id),
      messageType === "sent"
        ? eq(messages.type, "sent")
        : or(
            ne(messages.type, "sent"),
            isNull(messages.type)
          )
    )

    const totalResult = await db
      .select({ count: sql<number>`count(*)` })
      .from(messages)
      .where(baseConditions)

    const totalCount = Number(totalResult[0].count)
    const conditions = [baseConditions]

    if (cursorStr) {
      const { timestamp, id: cursorId } = decodeCursor(cursorStr)
      const orderByTime = messageType === "sent" ? messages.sentAt : messages.receivedAt
      conditions.push(
        or(
          lt(orderByTime, new Date(timestamp)),
          and(
            eq(orderByTime, new Date(timestamp)),
            lt(messages.id, cursorId)
          )
        )
      )
    }

    const orderByTime = messageType === "sent" ? messages.sentAt : messages.receivedAt

    const results = await db.query.messages.findMany({
      where: and(...conditions),
      orderBy: (messages, { desc }) => [
        desc(orderByTime),
        desc(messages.id)
      ],
      limit: PAGE_SIZE + 1
    })

    const hasMore = results.length > PAGE_SIZE
    const nextCursor = hasMore
      ? encodeCursor(
          messageType === "sent"
            ? results[PAGE_SIZE - 1].sentAt!.getTime()
            : results[PAGE_SIZE - 1].receivedAt.getTime(),
          results[PAGE_SIZE - 1].id
        )
      : null

    const messageList = hasMore ? results.slice(0, PAGE_SIZE) : results

    return new Response(JSON.stringify({
      messages: messageList.map(msg => ({
        id: msg.id,
        from_address: msg.fromAddress,
        to_address: msg.toAddress,
        subject: msg.subject,
        content: msg.content,
        html: msg.html,
        sent_at: msg.sentAt?.getTime(),
        received_at: msg.receivedAt?.getTime()
      })),
      nextCursor,
      total: totalCount
    }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
      }
    })
  } catch (error) {
    console.error("Failed to fetch messages:", error)
    return new Response(JSON.stringify({ error: "获取邮件失败" }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
      }
    })
  }
}
