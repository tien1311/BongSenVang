#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditAirport.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "302ed109636200b3c9cf3fbad43eeb0d7bcb3911"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Data_EditAirport), @"mvc.1.0.view", @"/Views/Data/EditAirport.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Data/EditAirport.cshtml", typeof(AspNetCore.Views_Data_EditAirport))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"302ed109636200b3c9cf3fbad43eeb0d7bcb3911", @"/Views/Data/EditAirport.cshtml")]
    public class Views_Data_EditAirport : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.Airport>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(35, 13, true);
            WriteLiteral("<style>\r\n    ");
            EndContext();
            BeginContext(49, 648, true);
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
            <h1 style=""color:red"">Chỉnh sửa sân bay</h1>
        </div>
        <div class=""modal-body"">
");
            EndContext();
#line 29 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditAirport.cshtml"
             using (Html.BeginForm("SaveEditAirport", "Data", new { i = 9 }, FormMethod.Post))
            {

#line default
#line hidden
            BeginContext(808, 279, true);
            WriteLiteral(@"                <div class=""row"">
                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">Sân bay</label>
                            <input type=""hidden"" name=""ID""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1087, "\"", 1104, 1);
#line 35 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditAirport.cshtml"
WriteAttributeValue("", 1095, Model.ID, 1095, 9, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1105, 70, true);
            WriteLiteral(">\r\n                            <input class=\"form-control\" name=\"Name\"");
            EndContext();
            BeginWriteAttribute("placeholder", " placeholder=\"", 1175, "\"", 1189, 0);
            EndWriteAttribute();
            BeginWriteAttribute("value", " value=\"", 1190, "\"", 1209, 1);
#line 36 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditAirport.cshtml"
WriteAttributeValue("", 1198, Model.Name, 1198, 11, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1210, 362, true);
            WriteLiteral(@">
                        </div>
                    </div>

                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">&nbsp;</label>
                            <div>
                                <button type=""submit"" class=""btn btn-primary""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1572, "\"", 1580, 0);
            EndWriteAttribute();
            BeginContext(1581, 135, true);
            WriteLiteral(">Lưu</button>\r\n                            </div>\r\n                        </div>\r\n                    </div>\r\n                </div>\r\n");
            EndContext();
#line 49 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditAirport.cshtml"
            }

#line default
#line hidden
            BeginContext(1731, 34, true);
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Models.Airport> Html { get; private set; }
    }
}
#pragma warning restore 1591