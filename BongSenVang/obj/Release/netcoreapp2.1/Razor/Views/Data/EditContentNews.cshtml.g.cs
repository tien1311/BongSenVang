#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "0509209b9dae297155bf0c011cf8690a78a567ad"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Data_EditContentNews), @"mvc.1.0.view", @"/Views/Data/EditContentNews.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Data/EditContentNews.cshtml", typeof(AspNetCore.Views_Data_EditContentNews))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"0509209b9dae297155bf0c011cf8690a78a567ad", @"/Views/Data/EditContentNews.cshtml")]
    public class Views_Data_EditContentNews : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.ArticleModel>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/vendors/jquery/dist/jquery.min.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/vendors/bootstrap/dist/js/bootstrap.min.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
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
            BeginContext(162, 13, true);
            WriteLiteral("<style>\r\n    ");
            EndContext();
            BeginContext(176, 327, true);
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
");
            EndContext();
            BeginContext(503, 59, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "0509209b9dae297155bf0c011cf8690a78a567ad4096", async() => {
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
            BeginContext(562, 22, true);
            WriteLiteral("\r\n<!-- Bootstrap -->\r\n");
            EndContext();
            BeginContext(584, 68, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "0509209b9dae297155bf0c011cf8690a78a567ad5296", async() => {
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
            BeginContext(652, 328, true);
            WriteLiteral(@"


<div class=""modal-dialog"">

    <!-- Modal content-->
    <div class=""modal-content"">
        <div class=""modal-header"">
            <button type=""button"" class=""close"" data-dismiss=""modal"">&times;</button>
            <h1 style=""color:red"">Chỉnh sửa bài viết</h1>
        </div>
        <div class=""modal-body"">
");
            EndContext();
#line 37 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml"
             using (Html.BeginForm("SaveEditContentNews", "Data", new { i = 9 }, FormMethod.Post))
            {

#line default
#line hidden
            BeginContext(1095, 350, true);
            WriteLiteral(@"                <div class=""row"">
                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">Danh mục</label>

                            <select name=""Danhmuc"" id=""Danhmuc"" class=""form-control"">
                                <option");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1445, "\"", 1470, 1);
#line 45 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml"
WriteAttributeValue("", 1453, Model.DanhMuc_ID, 1453, 17, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1471, 17, true);
            WriteLiteral(" selected hidden>");
            EndContext();
            BeginContext(1489, 18, false);
#line 45 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml"
                                                                             Write(Model.DanhMuc_Name);

#line default
#line hidden
            EndContext();
            BeginContext(1507, 11, true);
            WriteLiteral("</option>\r\n");
            EndContext();
#line 46 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml"
                                 foreach (var item in Model.ListSideMenu_Child)
                                {

#line default
#line hidden
            BeginContext(1634, 43, true);
            WriteLiteral("                                    <option");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1677, "\"", 1693, 1);
#line 48 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml"
WriteAttributeValue("", 1685, item.ID, 1685, 8, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1694, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(1696, 9, false);
#line 48 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml"
                                                        Write(item.Name);

#line default
#line hidden
            EndContext();
            BeginContext(1705, 11, true);
            WriteLiteral("</option>\r\n");
            EndContext();
#line 49 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml"
                                }

#line default
#line hidden
            BeginContext(1751, 343, true);
            WriteLiteral(@"                            </select>
                        </div>
                    </div>
                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">Tiêu đề</label>
                            <input type=""hidden"" name=""ID""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 2094, "\"", 2111, 1);
#line 56 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml"
WriteAttributeValue("", 2102, Model.ID, 2102, 9, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(2112, 71, true);
            WriteLiteral(">\r\n                            <input class=\"form-control\" name=\"Title\"");
            EndContext();
            BeginWriteAttribute("placeholder", " placeholder=\"", 2183, "\"", 2197, 0);
            EndWriteAttribute();
            BeginWriteAttribute("value", " value=\"", 2198, "\"", 2218, 1);
#line 57 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml"
WriteAttributeValue("", 2206, Model.Title, 2206, 12, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(2219, 656, true);
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
            BeginContext(2876, 21, false);
#line 71 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml"
                       Write(Model.Content_Article);

#line default
#line hidden
            EndContext();
            BeginContext(2897, 87, true);
            WriteLiteral("\r\n                    </textarea>\r\n                    </div>\r\n                </div>\r\n");
            EndContext();
#line 75 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditContentNews.cshtml"
            }

#line default
#line hidden
            BeginContext(2999, 247, true);
            WriteLiteral("        </div>\r\n    </div>\r\n</div>\r\n\r\n\r\n<script>\r\n    $(document).ready(function () {\r\n        CKEDITOR.replace(\'CreateContent\', {\r\n            height: 200,\r\n            filebrowserUploadUrl: \'/Data/UploadCKEditor\'\r\n        });\r\n    });\r\n</script>");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Models.ArticleModel> Html { get; private set; }
    }
}
#pragma warning restore 1591
