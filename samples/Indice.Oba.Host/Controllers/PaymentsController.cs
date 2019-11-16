using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Indice.Oba.Host.Models;
using Microsoft.AspNetCore.Mvc;

namespace Indice.Oba.Host.Controllers
{
    [ApiController]
    [Route("payments")]
    public class PaymentsController : ControllerBase
    {
        private static readonly ConcurrentDictionary<Guid, Payment> Payments = new ConcurrentDictionary<Guid, Payment>();

        [HttpPost]
        [ProducesResponseType(200, Type = typeof(Payment))]
        public IActionResult InitiatePayment(
            [FromHeader(Name = "X-Request-Id")] string requestId, 
            [FromHeader(Name = "Digest")] string digest,
            [FromHeader(Name = "Signature")] string signature,
            [FromHeader(Name = "TTP-Signature-Certificate")] string cert, 
            [FromBody]Payment payment) {
            payment.Status = "Initiated";
            Payments.TryAdd(payment.Id, payment);
            return Ok(payment);
        }

        [HttpPut("execute")]
        [ProducesResponseType(200, Type = typeof(void))]
        public IActionResult ExecutePayment(
            [FromHeader(Name = "X-Request-Id")] string requestId,
            [FromHeader(Name = "Digest")] string digest,
            [FromHeader(Name = "Signature")] string signature,
            [FromHeader(Name = "TTP-Signature-Certificate")] string cert,
            [FromBody]ExecutePaymentRequest request) {
            if (!Payments.TryGetValue(request.Id, out var payment)) {
                ModelState.AddModelError("", $"Invalid payment {request.Id}");
                return BadRequest(ModelState);
            }
            payment.Status = "Executed";
            return NoContent();
        }

        [HttpGet]
        [ProducesResponseType(200, Type = typeof(List<Payment>))]
        public IActionResult GetPayments(
            [FromHeader(Name = "X-Request-Id")] string requestId,
            [FromHeader(Name = "Digest")] string digest,
            [FromHeader(Name = "Signature")] string signature,
            [FromHeader(Name = "TTP-Signature-Certificate")] string cert,
            [FromQuery]string status = null) {
            return Ok(Payments.Values.Where(x => status == null || x.Status.Equals(status, StringComparison.OrdinalIgnoreCase)).ToList());
        }

        [HttpPost("test-client")]
        [ProducesResponseType(204, Type = typeof(void))]
        public IActionResult TestClient(
            [FromHeader(Name = "X-Request-Id")] string requestId,
            [FromHeader(Name = "Digest")] string digest,
            [FromHeader(Name = "Signature")] string signature,
            [FromHeader(Name = "TTP-Signature-Certificate")] string cert) {

            //var httpClient = new HttpClient(new HttpSignatureDelegatingHandler());
            
            return NoContent();
        }
    }
}
