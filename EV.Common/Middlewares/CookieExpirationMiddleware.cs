using EV.Common.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace EV.Common.Middlewares
{
    public class CookieExpirationMiddleware
    {
        private readonly RequestDelegate _next;
        private int _NumberCount = 0;

        public CookieExpirationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            var authResult = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            //if (!authResult.Succeeded || authResult?.Principal == null)
            //{
            //    await _next(context);
            //    return;
            //}

            // Kiểm tra tính hợp lệ của cookie
            var expirationDate = authResult.Properties?.ExpiresUtc;
            if(expirationDate.HasValue)
            {
                _NumberCount = 1;
                if (expirationDate.HasValue && expirationDate.Value < DateTime.UtcNow)
                {
                    _NumberCount = 0;
                    // Cookie hết hạn, chuyển hướng người dùng về trang đăng nhập
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    context.Response.Redirect("/Login/Index");
                    return;
                }
            }
            else
            {
                if (_NumberCount == 1)
                {
                    _NumberCount = 0;
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    context.Response.Redirect("/Login/Index");
                    return;
                }
            }
            await _next(context);
        }
    }
}
