// payload_dll.c -- 良性目标 DLL（内存 PE 加载器演示用）
// 无任何恶意/免杀行为: 只是落一个标记文件 + 后台线程弹个报到框。
#include <windows.h>

static DWORD WINAPI show_box(LPVOID p)
{
    (void)p;
    MessageBoxA(NULL,
        "This DLL was expanded into memory and executed by a\n"
        "hand-written PE loader (no LoadLibrary, no Windows loader).",
        "PE manual-map - OK", MB_OK | MB_ICONINFORMATION);
    return 0;
}

__declspec(dllexport) void RunMe(void)
{
    /* 硬证据: 由"被内存加载的 DLL"落一个标记文件 */
    HANDLE h = CreateFileA("mapped_marker.txt", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        const char* s = "RunMe() executed from a memory-mapped DLL (no LoadLibrary).\r\n";
        DWORD w = 0;
        WriteFile(h, s, (DWORD)lstrlenA(s), &w, NULL);
        CloseHandle(h);
    }
    /* 可见证据: 后台线程弹窗, 不阻塞 loader */
    HANDLE th = CreateThread(NULL, 0, show_box, NULL, 0, NULL);
    if (th) CloseHandle(th);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    (void)h; (void)reason; (void)reserved;
    return TRUE;
}
