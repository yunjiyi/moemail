import { NextResponse } from "next/server"
import { nanoid } from "nanoid"
import { createDb } from "@/lib/db"
import { emails } from "@/lib/schema"
import { eq, and, gt, sql } from "drizzle-orm"
import { EXPIRY_OPTIONS } from "@/types/email"
import { EMAIL_CONFIG } from "@/config"
import { getRequestContext } from "@cloudflare/next-on-pages"
import { getUserId } from "@/lib/apiKey"
import { getUserRole } from "@/lib/auth"
import { ROLES } from "@/lib/permissions"

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
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
    }
  })
}

export async function POST(request: Request) {
  const origin = request.headers.get("origin") || ""
  if (!isAllowed(request)) {
    return new Response("非法来源，禁止访问 API", {
      status: 403,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
      }
    })
  }

  const db = createDb()
  const env = getRequestContext().env
  const userId = await getUserId()
  const userRole = await getUserRole(userId!)

  try {
    if (userRole !== ROLES.EMPEROR) {
      const maxEmails = await env.SITE_CONFIG.get("MAX_EMAILS") || EMAIL_CONFIG.MAX_ACTIVE_EMAILS.toString()
      const activeEmailsCount = await db
        .select({ count: sql<number>`count(*)` })
        .from(emails)
        .where(
          and(
            eq(emails.userId, userId!),
            gt(emails.expiresAt, new Date())
          )
        )

      if (Number(activeEmailsCount[0].count) >= Number(maxEmails)) {
        return new Response(JSON.stringify({
          error: `已达到最大邮箱数量限制 (${maxEmails})`
        }), {
          status: 403,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
          }
        })
      }
    }

    const { name, expiryTime, domain } = await request.json<{
      name: string
      expiryTime: number
      domain: string
    }>()

    if (!EXPIRY_OPTIONS.some(option => option.value === expiryTime)) {
      return new Response(JSON.stringify({ error: "无效的过期时间" }), {
        status: 400,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
        }
      })
    }

    const domainString = await env.SITE_CONFIG.get("EMAIL_DOMAINS")
    const domains = domainString ? domainString.split(",") : ["moemail.app"]

    if (!domains.includes(domain)) {
      return new Response(JSON.stringify({ error: "无效的域名" }), {
        status: 400,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
        }
      })
    }

    const address = `${name || nanoid(8)}@${domain}`
    const existingEmail = await db.query.emails.findFirst({
      where: eq(sql`LOWER(${emails.address})`, address.toLowerCase())
    })

    if (existingEmail) {
      return new Response(JSON.stringify({ error: "该邮箱地址已被使用" }), {
        status: 409,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
        }
      })
    }

    const now = new Date()
    const expires = expiryTime === 0
      ? new Date("9999-01-01T00:00:00.000Z")
      : new Date(now.getTime() + expiryTime)

    const emailData: typeof emails.$inferInsert = {
      address,
      createdAt: now,
      expiresAt: expires,
      userId: userId!
    }

    const result = await db.insert(emails)
      .values(emailData)
      .returning({ id: emails.id, address: emails.address })

    return new Response(JSON.stringify({
      id: result[0].id,
      email: result[0].address
    }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
      }
    })
  } catch (error) {
    console.error("Failed to generate email:", error)
    return new Response(JSON.stringify({ error: "创建邮箱失败" }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key"
      }
    })
  }
}
