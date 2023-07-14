using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Indice.Psd2.Cryptography.X509Certificates.DerAsnTypes;

internal static class QueueExtensions
{
    public static IEnumerable<T> Dequeue<T>(this Queue<T> queue, long count) {
        for (long i = 0; i < count; i++) yield return queue.Dequeue();
    }

    public static IEnumerable<T> DequeueAll<T>(this Queue<T> queue) {
        while (queue.Any()) yield return queue.Dequeue();
    }
}
