#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Content\ViewContent.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "4186a7276de4ff633aff6faa315206988033a581"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Content_ViewContent), @"mvc.1.0.view", @"/Views/Content/ViewContent.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Content/ViewContent.cshtml", typeof(AspNetCore.Views_Content_ViewContent))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"4186a7276de4ff633aff6faa315206988033a581", @"/Views/Content/ViewContent.cshtml")]
    public class Views_Content_ViewContent : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.SubjectModel>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(0, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 3 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Content\ViewContent.cshtml"
  
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(101, 7, true);
            WriteLiteral("<title>");
            EndContext();
            BeginContext(109, 13, false);
#line 6 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Content\ViewContent.cshtml"
  Write(ViewBag.Title);

#line default
#line hidden
            EndContext();
            BeginContext(122, 257, true);
            WriteLiteral(@"</title>
<style type=""text/css"">
    .resize div {
        width: unset !important;
    }
</style>
<div class=""row"">
    <div class=""x_panel"">
        <div class=""x_content"">
            <div id=""resize_image"" class=""resize"">
                <div>");
            EndContext();
            BeginContext(380, 31, false);
#line 16 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Content\ViewContent.cshtml"
                Write(Html.Raw(Model.subject_content));

#line default
#line hidden
            EndContext();
            BeginContext(411, 62, true);
            WriteLiteral("</div>\r\n            </div>\r\n        </div>\r\n    </div>\r\n</div>");
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
