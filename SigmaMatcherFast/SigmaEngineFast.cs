using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SigmaMatcherFast.Sigma
{
    public sealed unsafe class SigmaEngineFast : IDisposable
    {
        private IntPtr _handle;
        private string[] _rulePaths;

        public string[] RulePaths => _rulePaths ?? Array.Empty<string>();

        public SigmaEngineFast(string rulesDir)
        {
            if (string.IsNullOrWhiteSpace(rulesDir))
                throw new ArgumentException("rulesDir is empty");

            byte[] r = SigmaNative.Utf8Bytes(rulesDir);

            fixed (byte* rPtr = r)
            {
                _handle = SigmaNative.sigma_init(rPtr, (UIntPtr)r.Length);
            }

            if (_handle == IntPtr.Zero)
                throw new Exception("sigma_init failed: " + SigmaNative.TakeLastError());
        }

        public void Dispose()
        {
            if (_handle != IntPtr.Zero)
            {
                SigmaNative.sigma_destroy(_handle);
                _handle = IntPtr.Zero;
            }
        }

        public void Reload()
        {
            Ensure();
            int ok = SigmaNative.sigma_reload(_handle);
            if (ok == 0)
                throw new Exception("sigma_reload failed: " + SigmaNative.TakeLastError());

            _rulePaths = null;
        }

        public string[] LoadRulePathsOnce()
        {
            Ensure();
            if (_rulePaths != null) return _rulePaths;

            var buf = SigmaNative.sigma_get_rule_paths(_handle);
            if (buf.ptr == IntPtr.Zero)
                throw new Exception("sigma_get_rule_paths failed: " + SigmaNative.TakeLastError());

            try
            {
                byte* p = (byte*)buf.ptr.ToPointer();
                byte* end = p + (int)buf.len;

                uint count = ReadU32(ref p, end);
                var arr = new string[count];

                for (uint i = 0; i < count; i++)
                {
                    uint len = ReadU32(ref p, end);
                    if (p + len > end) throw new Exception("Corrupt rule_paths buffer");

                    byte[] tmp = new byte[len];
                    Marshal.Copy((IntPtr)p, tmp, 0, (int)len);
                    arr[i] = Encoding.UTF8.GetString(tmp);

                    p += len;
                }

                _rulePaths = arr;
                return arr;
            }
            finally
            {
                SigmaNative.sigma_free_buffer(buf);
            }
        }

        public void ScanJsonlFile(string jsonlPath, bool includeLine, Action<Hit> onHit, uint maxLineBytes = 4096)
        {
            Ensure();
            if (onHit == null) throw new ArgumentNullException(nameof(onHit));
            if (string.IsNullOrWhiteSpace(jsonlPath))
                throw new ArgumentException("jsonlPath is empty");

            if (_rulePaths == null) LoadRulePathsOnce();

            byte[] pathBytes = SigmaNative.Utf8Bytes(jsonlPath);

            SigmaNative.SigmaBuffer buf;
            fixed (byte* pPath = pathBytes)
            {
                buf = SigmaNative.sigma_scan_jsonl_file(
                    _handle,
                    pPath,
                    (UIntPtr)pathBytes.Length,
                    includeLine ? (byte)1 : (byte)0,
                    maxLineBytes);
            }

            if (buf.ptr == IntPtr.Zero)
                throw new Exception("sigma_scan_jsonl_file failed: " + SigmaNative.TakeLastError());

            try
            {
                byte* p = (byte*)buf.ptr.ToPointer();
                byte* end = p + (int)buf.len;

                uint version = ReadU32(ref p, end);
                uint hitCount = ReadU32(ref p, end);

                if (version != 1)
                    throw new Exception("Bad buffer version: " + version);

                for (uint i = 0; i < hitCount; i++)
                {
                    uint lineNo = ReadU32(ref p, end);
                    uint ruleIdx = ReadU32(ref p, end);
                    uint lineLen = ReadU32(ref p, end);

                    if (p + lineLen > end) throw new Exception("Corrupt hits buffer");

                    string line = null;
                    if (includeLine && lineLen > 0)
                    {
                        byte[] tmp = new byte[lineLen];
                        Marshal.Copy((IntPtr)p, tmp, 0, (int)lineLen);
                        line = Encoding.UTF8.GetString(tmp);
                    }

                    p += lineLen;

                    string rulePath = (ruleIdx < (uint)_rulePaths.Length)
                        ? _rulePaths[ruleIdx]
                        : "<unknown>";

                    onHit(new Hit(jsonlPath, lineNo, ruleIdx, rulePath, line));
                }
            }
            finally
            {
                SigmaNative.sigma_free_buffer(buf);
            }
        }
        public List<Hit> ScanJsonlFileToList(string jsonlPath, bool includeLine, uint maxLineBytes = 4096)
        {
            var list = new List<Hit>(256);
            ScanJsonlFile(jsonlPath, includeLine, h => list.Add(h), maxLineBytes);
            return list;
        }

        public List<InvalidRule> GetInvalidRules()
        {
            Ensure();

            var buf = SigmaNative.sigma_get_invalid_rules(_handle);
            if (buf.ptr == IntPtr.Zero)
                throw new Exception("sigma_get_invalid_rules failed: " + SigmaNative.TakeLastError());

            try
            {
                byte* p = (byte*)buf.ptr.ToPointer();
                byte* end = p + (int)buf.len;

                uint count = ReadU32(ref p, end);
                var list = new List<InvalidRule>((int)count);

                for (uint i = 0; i < count; i++)
                {
                    uint pathLen = ReadU32(ref p, end);
                    string path = ReadUtf8String(ref p, end, pathLen);

                    uint errLen = ReadU32(ref p, end);
                    string err = ReadUtf8String(ref p, end, errLen);

                    list.Add(new InvalidRule(path, err));
                }

                return list;
            }
            finally
            {
                SigmaNative.sigma_free_buffer(buf);
            }
        }

        private void Ensure()
        {
            if (_handle == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(SigmaEngineFast));
        }

        private static uint ReadU32(ref byte* p, byte* end)
        {
            if (p + 4 > end) throw new Exception("Buffer underrun");
            uint v = (uint)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
            p += 4;
            return v;
        }

        private static string ReadUtf8String(ref byte* p, byte* end, uint len)
        {
            if (p + len > end) throw new Exception("Buffer underrun");
            byte[] tmp = new byte[len];
            Marshal.Copy((IntPtr)p, tmp, 0, (int)len);
            p += len;
            return Encoding.UTF8.GetString(tmp);
        }

        public readonly struct Hit
        {
            public readonly string FilePath;
            public readonly uint LineNo;
            public readonly uint RuleIndex;
            public readonly string RulePath;
            public readonly string Line;

            public Hit(string filePath, uint lineNo, uint ruleIndex, string rulePath, string line)
            {
                FilePath = filePath;
                LineNo = lineNo;
                RuleIndex = ruleIndex;
                RulePath = rulePath;
                Line = line;
            }
        }

        public readonly struct InvalidRule
        {
            public readonly string Path;
            public readonly string Error;

            public InvalidRule(string path, string error)
            {
                Path = path;
                Error = error;
            }
        }
    }
}
