#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Noibo\DetailNews.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "490df09af9a9a127c48175e7fe1aee0ee69ac216"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Noibo_DetailNews), @"mvc.1.0.view", @"/Views/Noibo/DetailNews.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Noibo/DetailNews.cshtml", typeof(AspNetCore.Views_Noibo_DetailNews))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"490df09af9a9a127c48175e7fe1aee0ee69ac216", @"/Views/Noibo/DetailNews.cshtml")]
    public class Views_Noibo_DetailNews : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.SubjectModel>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#line 2 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Noibo\DetailNews.cshtml"
  
    ViewData["Title"] = "Chi Tiết Tin";
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(140, 7, true);
            WriteLiteral("<title>");
            EndContext();
            BeginContext(148, 13, false);
#line 6 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Noibo\DetailNews.cshtml"
  Write(ViewBag.Title);

#line default
#line hidden
            EndContext();
            BeginContext(161, 252, true);
            WriteLiteral("</title>\r\n<style type=\"text/css\">\r\n    .resize div {\r\n        width: unset !important;\r\n    }\r\n</style>\r\n<div class=\"row\">\r\n    <div class=\"x_panel\">\r\n        <div class=\"x_content\">\r\n            <div id=\"resize_image\" class=\"resize\">\r\n                ");
            EndContext();
            BeginContext(414, 11, false);
#line 16 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Noibo\DetailNews.cshtml"
           Write(Model.Title);

#line default
#line hidden
            EndContext();
            BeginContext(425, 27, true);
            WriteLiteral("<br>\r\n                <div>");
            EndContext();
            BeginContext(453, 31, false);
#line 17 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Noibo\DetailNews.cshtml"
                Write(Html.Raw(Model.subject_content));

#line default
#line hidden
            EndContext();
            BeginContext(484, 8, true);
            WriteLiteral("</div>\r\n");
            EndContext();
#line 18 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Noibo\DetailNews.cshtml"
                 if(Model.subject_name != null && Model.subject_name != "")
                {

#line default
#line hidden
            BeginContext(588, 22, true);
            WriteLiteral("                    <a");
            EndContext();
            BeginWriteAttribute("href", " href=\"", 610, "\"", 678, 2);
            WriteAttributeValue("", 617, "http://daily.airline24h.com/upload/bantin/", 617, 42, true);
#line 20 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Noibo\DetailNews.cshtml"
WriteAttributeValue("", 659, Model.subject_name, 659, 19, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(679, 60, true);
            WriteLiteral(" style=\"color:blue\" target=\"_blank\">link file đính kèm</a>\r\n");
            EndContext();
#line 21 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Noibo\DetailNews.cshtml"
                }

#line default
#line hidden
            BeginContext(758, 54, true);
            WriteLiteral("            </div>\r\n        </div>\r\n    </div>\r\n</div>");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Models.SubjectModel> Html { get; private set; }
    }
}
#pragma warning restore 1591
