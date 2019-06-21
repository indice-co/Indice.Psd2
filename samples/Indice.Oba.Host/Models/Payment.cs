using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Indice.Oba.Host.Models
{
    public class Payment
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public decimal Amount { get; set; }
        public DateTime Date { get; set; }
        public string Status { get; set; }
    }

    public class ExecutePaymentRequest
    {
        public Guid Id { get; set; }
    }

    public class PaymentStatusResponse
    {
        public string Status { get; set; }
    }
}
