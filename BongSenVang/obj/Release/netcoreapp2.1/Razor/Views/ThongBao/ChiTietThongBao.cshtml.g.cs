#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\ThongBao\ChiTietThongBao.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "7726cd87f69eac8e0ac607f4581cbce817648c8d"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_ThongBao_ChiTietThongBao), @"mvc.1.0.view", @"/Views/ThongBao/ChiTietThongBao.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/ThongBao/ChiTietThongBao.cshtml", typeof(AspNetCore.Views_ThongBao_ChiTietThongBao))]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#line 4 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\ThongBao\ChiTietThongBao.cshtml"
using Microsoft.AspNetCore.Html;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"7726cd87f69eac8e0ac607f4581cbce817648c8d", @"/Views/ThongBao/ChiTietThongBao.cshtml")]
    public class Views_ThongBao_ChiTietThongBao : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.ChiTietTB>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(0, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(39, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(75, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 6 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\ThongBao\ChiTietThongBao.cshtml"
  
    ViewBag.NoiDung = new HtmlString(Model.NoiDung);

#line default
#line hidden
            BeginContext(138, 453, true);
            WriteLiteral(@"
<div class=""modal-dialog"" style=""margin-top:100px;"">

    <!-- Modal content-->
    <div class=""modal-content"">
        <div class=""modal-header"">
            <button type=""button"" class=""close"" data-dismiss=""modal"">&times;</button>
            <h1 style=""color:red"">Nội dung thông báo</h1>
        </div>

        <div class=""form-horizontal"" role=""form"">
            <div class=""form-group"" style=""padding:0 20px;"">
                <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 591, "\"", 597, 0);
            EndWriteAttribute();
            BeginContext(598, 137, true);
            WriteLiteral(" class=\"col-sm-12 control-label\" style=\"text-align:left\">Nội dung:</label>\r\n                <div class=\"col-sm-12\">\r\n                    ");
            EndContext();
            BeginContext(736, 15, false);
#line 23 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\ThongBao\ChiTietThongBao.cshtml"
               Write(ViewBag.NoiDung);

#line default
#line hidden
            EndContext();
            BeginContext(751, 236, true);
            WriteLiteral(";\r\n                </div>\r\n            </div>\r\n        </div>\r\n\r\n        <div class=\"modal-footer\">\r\n            <button type=\"button\" class=\"btn btn-secondary\" data-dismiss=\"modal\">Close</button>\r\n        </div>\r\n    </div>\r\n</div>\r\n\r\n");
            EndContext();
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Models.ChiTietTB> Html { get; private set; }
    }
}
#pragma warning restore 1591
