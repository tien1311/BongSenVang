#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\CreateMenuChild.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "75b9f345615f401ff782ee691eaff6616c78f1c2"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Data_CreateMenuChild), @"mvc.1.0.view", @"/Views/Data/CreateMenuChild.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Data/CreateMenuChild.cshtml", typeof(AspNetCore.Views_Data_CreateMenuChild))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"75b9f345615f401ff782ee691eaff6616c78f1c2", @"/Views/Data/CreateMenuChild.cshtml")]
    public class Views_Data_CreateMenuChild : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<List<BongSenVang.Models.SideMenu_ParentModel>>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(54, 13, true);
            WriteLiteral("<style>\r\n    ");
            EndContext();
            BeginContext(68, 651, true);
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
            <h1 style=""color:red"">Tạo mới danh mục con</h1>
        </div>
        <div class=""modal-body"">
");
            EndContext();
#line 29 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\CreateMenuChild.cshtml"
             using (Html.BeginForm("SaveCreateMenuChild", "Data", new { i = 9 }, FormMethod.Post))
            {

#line default
#line hidden
            BeginContext(834, 315, true);
            WriteLiteral(@"                <div class=""row"">
                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">Danh mục cha</label>

                            <select name=""Danhmuc"" id=""Danhmuc"" class=""form-control"">
");
            EndContext();
#line 37 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\CreateMenuChild.cshtml"
                                 foreach (var item in Model)
                                {

#line default
#line hidden
            BeginContext(1246, 43, true);
            WriteLiteral("                                    <option");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1289, "\"", 1305, 1);
#line 39 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\CreateMenuChild.cshtml"
WriteAttributeValue("", 1297, item.ID, 1297, 8, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1306, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(1308, 9, false);
#line 39 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\CreateMenuChild.cshtml"
                                                        Write(item.Name);

#line default
#line hidden
            EndContext();
            BeginContext(1317, 11, true);
            WriteLiteral("</option>\r\n");
            EndContext();
#line 40 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\CreateMenuChild.cshtml"
                                }

#line default
#line hidden
            BeginContext(1363, 361, true);
            WriteLiteral(@"                            </select>
                        </div>
                    </div>
                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">Tên danh mục con</label>
                            <input class=""form-control"" name=""Name""");
            EndContext();
            BeginWriteAttribute("placeholder", " placeholder=\"", 1724, "\"", 1738, 0);
            EndWriteAttribute();
            BeginContext(1739, 535, true);
            WriteLiteral(@">
                        </div>
                    </div>

                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">&nbsp;</label>
                            <div>
                                <button type=""submit"" class=""btn btn-primary"" name=""searchKH"" value=""searchBtn"">Tạo mới</button>
                            </div>
                        </div>
                    </div>
                </div>
");
            EndContext();
#line 60 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\CreateMenuChild.cshtml"
            }

#line default
#line hidden
            BeginContext(2289, 34, true);
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<List<BongSenVang.Models.SideMenu_ParentModel>> Html { get; private set; }
    }
}
#pragma warning restore 1591
