#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\Tieude.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "54db8da2ddb7bfa81b6d750d68dae0564626b491"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_KinhDoanh_Tieude), @"mvc.1.0.view", @"/Views/KinhDoanh/Tieude.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/KinhDoanh/Tieude.cshtml", typeof(AspNetCore.Views_KinhDoanh_Tieude))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"54db8da2ddb7bfa81b6d750d68dae0564626b491", @"/Views/KinhDoanh/Tieude.cshtml")]
    public class Views_KinhDoanh_Tieude : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<List<BongSenVang.Models.ListTieuDe>>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#line 2 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\Tieude.cshtml"
 if (Model != null)
{

#line default
#line hidden
            BeginContext(68, 44, true);
            WriteLiteral("    <div class=\"form-group\">\r\n        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 112, "\"", 118, 0);
            EndWriteAttribute();
            BeginContext(119, 172, true);
            WriteLiteral(" class=\"col-sm-2 control-label\">Loại</label>\r\n        <div class=\"col-sm-10\">\r\n            <input type=\"hidden\" class=\"form-control\" id=\"IDNoiDungKhoa\" name=\"IDNoiDungKhoa\"");
            EndContext();
            BeginWriteAttribute("placeholder", " placeholder=\"", 291, "\"", 305, 0);
            EndWriteAttribute();
            BeginWriteAttribute("value", " value=\"", 306, "\"", 314, 0);
            EndWriteAttribute();
            BeginContext(315, 188, true);
            WriteLiteral(">\r\n            <select id=\"ChuDe\" name=\"ChuDe\" asp-for=\"ChuDe\" class=\"select2_single form-control\" onchange=\"getNoiDung()\">\r\n                <option value=\"0\">-- Chọn tiêu đề --</option>\r\n");
            EndContext();
#line 10 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\Tieude.cshtml"
                 foreach (var item in Model)
                {

#line default
#line hidden
            BeginContext(568, 27, true);
            WriteLiteral("                    <option");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 595, "\"", 614, 1);
#line 12 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\Tieude.cshtml"
WriteAttributeValue("", 603, item.RowID, 603, 11, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(615, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(617, 11, false);
#line 12 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\Tieude.cshtml"
                                           Write(item.TieuDe);

#line default
#line hidden
            EndContext();
            BeginContext(628, 11, true);
            WriteLiteral("</option>\r\n");
            EndContext();
#line 13 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\Tieude.cshtml"
                }

#line default
#line hidden
            BeginContext(658, 284, true);
            WriteLiteral(@"
            </select>

        </div>
        <div class=""form-group"">
            <div class=""col-sm-10"">
                <textarea class=""form-control"" readonly name=""noiDungKhoatxt"" id=""noiDungKhoatxt"" rows=""6""></textarea>

            </div>
        </div>
    </div>
");
            EndContext();
#line 25 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\Tieude.cshtml"
}
else
{

#line default
#line hidden
            BeginContext(954, 44, true);
            WriteLiteral("    <div class=\"form-group\">\r\n        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 998, "\"", 1004, 0);
            EndWriteAttribute();
            BeginContext(1005, 172, true);
            WriteLiteral(" class=\"col-sm-2 control-label\">Loại</label>\r\n        <div class=\"col-sm-10\">\r\n            <input type=\"hidden\" class=\"form-control\" id=\"IDNoiDungKhoa\" name=\"IDNoiDungKhoa\"");
            EndContext();
            BeginWriteAttribute("placeholder", " placeholder=\"", 1177, "\"", 1191, 0);
            EndWriteAttribute();
            BeginWriteAttribute("value", " value=\"", 1192, "\"", 1200, 0);
            EndWriteAttribute();
            BeginContext(1201, 239, true);
            WriteLiteral(">\r\n            <select id=\"ChuDe\" name=\"ChuDe\" asp-for=\"ChuDe\" class=\"select2_single form-control\" onchange=\"getNoiDung()\">\r\n                <option value=\"0\">-- Chọn tiêu đề --</option>\r\n            </select>\r\n        </div>\r\n    </div>\r\n");
            EndContext();
#line 37 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\Tieude.cshtml"
}

#line default
#line hidden
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<List<BongSenVang.Models.ListTieuDe>> Html { get; private set; }
    }
}
#pragma warning restore 1591
