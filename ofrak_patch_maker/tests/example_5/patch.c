extern char debug_string;
extern void debug_printf(const char *format, ...);

int patch(void) {
    debug_printf(&debug_string);
    return 0;
}
