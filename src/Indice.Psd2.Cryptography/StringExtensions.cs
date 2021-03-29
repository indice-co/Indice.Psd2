namespace Indice.Psd2.Cryptography
{
    internal static class StringExtensions
    {
        public static string EnsureLeadingSlash(this string path) => $"/{path.TrimStart('/')}";
    }
}
