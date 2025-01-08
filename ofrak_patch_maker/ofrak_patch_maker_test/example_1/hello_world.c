#if __GNUC__
__attribute__((section(".bss.new")))
#endif // __GNUC__
int global_arr[64] = {0};

#if __GNUC__
__attribute__((section(".bss.legacy")))
#endif // __GNUC__
int global_arr_legacy[256] = {0};

int main_supplement(int a, int b)
{
    if (a*b > 49) {
        global_arr[3] = 1;
    }
    return a*b;
}

int foo(int* arr) {
    return arr[48];
}

#ifdef __GNUC__
__attribute__((section(".text")))
#endif // __GNUC__
int main(void) {
    int a = 49;
    int b = 29;
    int c = -38;
    int d = main_supplement(a, b) * c;
    (void) d;
    return foo(global_arr_legacy);
}
