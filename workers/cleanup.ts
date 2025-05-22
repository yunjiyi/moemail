interface Env {
  DB: D1Database
}

const CLEANUP_CONFIG = {
  // Whether to delete expired emails
  DELETE_EXPIRED_EMAILS: true,
  
  // Batch processing size
  BATCH_SIZE: 100,
} as const 

const main = {
  async scheduled(event: ScheduledEvent, env: Env) {
    const now = Date.now()

    try {
      if (!CLEANUP_CONFIG.DELETE_EXPIRED_EMAILS) {
        console.log('Expired email deletion is disabled')
        return
      }

      // Directly delete expired emails (messages will be cascade-deleted via foreign key constraint)
      const result = await env.DB
        .prepare(`
          DELETE FROM email 
          WHERE expires_at < ?
          LIMIT ?
          RETURNING id
        `)
        .bind(now, CLEANUP_CONFIG.BATCH_SIZE)
        .run()

      const deletedCount = result?.meta?.changes || 0
      console.log(`Deleted ${deletedCount} expired emails and their associated messages`)
      
    } catch (error) {
      console.error('Failed to cleanup:', error)
      throw error
    }
  }
}

export default main
