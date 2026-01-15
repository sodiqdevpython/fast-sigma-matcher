using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SigmaMatcherFast.Sigma
{
    internal static unsafe class SigmaNative
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct SigmaBuffer
        {
            public IntPtr ptr;
            public UIntPtr len;
        }

        private const string Dll = "sigma_runner";

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sigma_init(byte* rulesPtr, UIntPtr rulesLen);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern SigmaBuffer sigma_eval_json_line(
            IntPtr handle,
            byte* jsonPtr,
            UIntPtr jsonLen,
            byte includeLine,
            uint maxLineBytes);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sigma_destroy(IntPtr handle);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sigma_reload(IntPtr handle);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern SigmaBuffer sigma_get_rule_paths(IntPtr handle);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern SigmaBuffer sigma_get_invalid_rules(IntPtr handle);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern SigmaBuffer sigma_scan_jsonl_file(
            IntPtr handle,
            byte* pathPtr,
            UIntPtr pathLen,
            byte includeLine,
            uint maxLineBytes);

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern SigmaBuffer sigma_take_last_error();

        [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sigma_free_buffer(SigmaBuffer buf);

        internal static byte[] Utf8Bytes(string s) => Encoding.UTF8.GetBytes(s ?? "");

        internal static string TakeLastError()
        {
            SigmaBuffer b = sigma_take_last_error();
            if (b.ptr == IntPtr.Zero || b.len == UIntPtr.Zero) return "Unknown error";

            try
            {
                int n = checked((int)b.len);
                byte[] tmp = new byte[n];
                Marshal.Copy(b.ptr, tmp, 0, n);
                return Encoding.UTF8.GetString(tmp);
            }
            finally
            {
                sigma_free_buffer(b);
            }
        }
    }
}
