#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\CreateMenuParent.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "d1e4e46383a57efd86c398b5834d5aeb276e01e1"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Data_CreateMenuParent), @"mvc.1.0.view", @"/Views/Data/CreateMenuParent.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Data/CreateMenuParent.cshtml", typeof(AspNetCore.Views_Data_CreateMenuParent))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"d1e4e46383a57efd86c398b5834d5aeb276e01e1", @"/Views/Data/CreateMenuParent.cshtml")]
    public class Views_Data_CreateMenuParent : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(0, 13, true);
            WriteLiteral("<style>\r\n    ");
            EndContext();
            BeginContext(14, 651, true);
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
            <h1 style=""color:red"">Tạo mới danh mục cha</h1>
        </div>
        <div class=""modal-body"">
");
            EndContext();
#line 28 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\CreateMenuParent.cshtml"
             using (Html.BeginForm("SaveCreateMenuParent", "Data", new { i = 9 }, FormMethod.Post))
            {

#line default
#line hidden
            BeginContext(781, 289, true);
            WriteLiteral(@"                <div class=""row"">
                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">Danh mục</label>
                            <input class=""form-control"" name=""Name""");
            EndContext();
            BeginWriteAttribute("placeholder", " placeholder=\"", 1070, "\"", 1084, 0);
            EndWriteAttribute();
            BeginContext(1085, 519, true);
            WriteLiteral(@">
                        </div>
                    </div>

                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">&nbsp;</label>
                            <div>
                                <button type=""submit"" class=""btn btn-primary"" value=""searchBtn"">Tạo mới</button>
                            </div>
                        </div>
                    </div>
                </div>
");
            EndContext();
#line 47 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\CreateMenuParent.cshtml"
            }

#line default
#line hidden
            BeginContext(1619, 34, true);
            WriteLiteral("        </div>\r\n    </div>\r\n</div>");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<dynamic> Html { get; private set; }
    }
}
#pragma warning restore 1591
