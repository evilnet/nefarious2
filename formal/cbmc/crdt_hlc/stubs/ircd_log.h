/* Harness stub: log_write is a no-op for verification. */
enum LogSys { LS_SYSTEM };
enum LogLevel { L_WARNING };
static void log_write(enum LogSys s, enum LogLevel l, unsigned int f, const char *fmt, ...) { (void)s; (void)l; (void)f; (void)fmt; }
