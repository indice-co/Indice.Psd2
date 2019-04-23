using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Indice.Oba.Host.Swagger;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Indice.Oba.Host
{
    public class Startup
    {
        public Startup(IConfiguration configuration) {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services) {
            services.AddMvc()
                    .SetCompatibilityVersion(CompatibilityVersion.Version_2_2)
                    .AddCertificateEndpoints(x => {
                        x.IssuerDomain = "localhost:5000";
                        x.AddEntitiyFrameworkStore(options => {
                            options.ConfigureDbContext = (a) => {
                                a.UseSqlServer(Configuration.GetConnectionString("CertificatesDb"));
                            };
                        });
                    });

            services.AddSwaggerGen(x => {
                x.SchemaFilter<SchemaExamplesFilter>();
                x.SwaggerDoc("cert", new Microsoft.OpenApi.Models.OpenApiInfo() {
                    Description = "Certificate *utilities*",
                    Title = "Certificate",
                    Version = "v1"
                });
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env) {
            if (env.IsDevelopment()) {
                app.UseDeveloperExceptionPage();
            } else {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseSwagger();
            app.UseSwaggerUI(x => {
                x.RoutePrefix = "swagger/ui";
                x.SwaggerEndpoint($"/swagger/cert/swagger.json", "cert");
            });
            app.UseMvc();

        }
    }
}
