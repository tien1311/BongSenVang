#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditNhomDL.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "161325533f164a0b3204ed4bd4b6bfcc243bb425"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Data_EditNhomDL), @"mvc.1.0.view", @"/Views/Data/EditNhomDL.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Data/EditNhomDL.cshtml", typeof(AspNetCore.Views_Data_EditNhomDL))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"161325533f164a0b3204ed4bd4b6bfcc243bb425", @"/Views/Data/EditNhomDL.cshtml")]
    public class Views_Data_EditNhomDL : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.NhomDL>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/js/jquery.1.7.2.min.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/vendors/ckeditor/ckeditor.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        #pragma warning restore 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(34, 13, true);
            WriteLiteral("<style>\r\n    ");
            EndContext();
            BeginContext(48, 652, true);
            WriteLiteral(@"@media(min-width: 768px) {
        .modal-dialog {
            width: 800px;
            margin: 30px auto;
        }
    }

    .modal-body img {
        width: 100% !important;
        height: auto !important;
    }

    .modal-header {
        padding: 6px 15px;
        border-bottom: none;
    }
</style>
<div class=""modal-dialog"">

    <!-- Modal content-->
    <div class=""modal-content"">
        <div class=""modal-header"">
            <button type=""button"" class=""close"" data-dismiss=""modal"">&times;</button>
            <h1 style=""color:red"">Chỉnh sửa nhóm đại lý</h1>
        </div>
        <div class=""modal-body"">
");
            EndContext();
#line 29 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditNhomDL.cshtml"
             using (Html.BeginForm("SaveEditNhomDL", "Data", new { i = 9 }, FormMethod.Post))
            {

#line default
#line hidden
            BeginContext(810, 279, true);
            WriteLiteral(@"                <div class=""row"">
                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">Tên Vip</label>
                            <input name=""ID"" type=""hidden""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1089, "\"", 1110, 1);
#line 35 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditNhomDL.cshtml"
WriteAttributeValue("", 1097, Model.IDNhom, 1097, 13, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1111, 71, true);
            WriteLiteral(">\r\n                            <input class=\"form-control\" name=\"Title\"");
            EndContext();
            BeginWriteAttribute("placeholder", " placeholder=\"", 1182, "\"", 1196, 0);
            EndWriteAttribute();
            BeginWriteAttribute("value", " value=\"", 1197, "\"", 1219, 1);
#line 36 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditNhomDL.cshtml"
WriteAttributeValue("", 1205, Model.TenNhom, 1205, 14, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1220, 656, true);
            WriteLiteral(@">
                        </div>
                    </div>

                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">&nbsp;</label>
                            <div>
                                <button type=""submit"" class=""btn btn-primary"" name=""searchKH"" value=""searchBtn"">Lưu</button>
                            </div>
                        </div>
                    </div>
                    <div class=""col-sm-12"">
                        <textarea name=""CreateContent"" id=""CreateContent"">
                            ");
            EndContext();
            BeginContext(1877, 23, false);
#line 50 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditNhomDL.cshtml"
                       Write(Html.Raw(Model.NoiDung));

#line default
#line hidden
            EndContext();
            BeginContext(1900, 92, true);
            WriteLiteral(" \r\n                        </textarea>\r\n                    </div>\r\n                </div>\r\n");
            EndContext();
#line 54 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditNhomDL.cshtml"
            }

#line default
#line hidden
            BeginContext(2007, 36, true);
            WriteLiteral("        </div>\r\n    </div>\r\n</div>\r\n");
            EndContext();
            BeginContext(2043, 48, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "161325533f164a0b3204ed4bd4b6bfcc243bb4257367", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_0);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(2091, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(2093, 54, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "161325533f164a0b3204ed4bd4b6bfcc243bb4258546", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_1);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(2147, 217, true);
            WriteLiteral("\r\n<script>\r\n    $(document).ready(function () {\r\n            CKEDITOR.replace(\'CreateContent\', {\r\n            height: 200,\r\n            filebrowserUploadUrl: \'/Data/UploadCKEditor\'\r\n        });\r\n    });\r\n</script>\r\n\r\n");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Models.NhomDL> Html { get; private set; }
    }
}
#pragma warning restore 1591
