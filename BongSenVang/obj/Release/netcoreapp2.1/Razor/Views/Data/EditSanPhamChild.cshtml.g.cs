#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditSanPhamChild.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "71c58a8ee15850bc60e3b04ae5dd7cc9e70f7c5e"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Data_EditSanPhamChild), @"mvc.1.0.view", @"/Views/Data/EditSanPhamChild.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Data/EditSanPhamChild.cshtml", typeof(AspNetCore.Views_Data_EditSanPhamChild))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"71c58a8ee15850bc60e3b04ae5dd7cc9e70f7c5e", @"/Views/Data/EditSanPhamChild.cshtml")]
    public class Views_Data_EditSanPhamChild : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.SanPhamChild>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-controller", "Data", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-route-i", "9", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_2 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("asp-action", "SaveEditSanPhamChild", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_3 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("method", "post", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_4 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("enctype", new global::Microsoft.AspNetCore.Html.HtmlString("multipart/form-data"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
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
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper;
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(94, 13, true);
            WriteLiteral("<style>\r\n    ");
            EndContext();
            BeginContext(108, 663, true);
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
            <h1 style=""color:red"">Tạo mới sản phẩm con</h1>
        </div>
        <div class=""modal-body"">
            ");
            EndContext();
            BeginContext(771, 2823, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("form", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "71c58a8ee15850bc60e3b04ae5dd7cc9e70f7c5e5396", async() => {
                BeginContext(893, 295, true);
                WriteLiteral(@"
                <div class=""row"">
                    <div class=""col-sm-4"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">Tên sản phẩm</label>
                            <input class=""form-control"" name=""Name""");
                EndContext();
                BeginWriteAttribute("placeholder", " placeholder=\"", 1188, "\"", 1202, 0);
                EndWriteAttribute();
                BeginWriteAttribute("value", " value=\"", 1203, "\"", 1222, 1);
#line 35 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditSanPhamChild.cshtml"
WriteAttributeValue("", 1211, Model.Name, 1211, 11, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(1223, 61, true);
                WriteLiteral(">\r\n                            <input type=\"hidden\" name=\"ID\"");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 1284, "\"", 1301, 1);
#line 36 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditSanPhamChild.cshtml"
WriteAttributeValue("", 1292, Model.ID, 1292, 9, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(1302, 322, true);
                WriteLiteral(@" />
                        </div>
                    </div>
                    <div class=""col-sm-3"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">Giá show</label>
                            <input class=""form-control"" name=""GiaShow""");
                EndContext();
                BeginWriteAttribute("placeholder", " placeholder=\"", 1624, "\"", 1638, 0);
                EndWriteAttribute();
                BeginWriteAttribute("value", " value=\"", 1639, "\"", 1659, 1);
#line 42 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditSanPhamChild.cshtml"
WriteAttributeValue("", 1647, Model.Price, 1647, 12, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(1660, 323, true);
                WriteLiteral(@">
                        </div>
                    </div>
                    <div class=""col-sm-3"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">Giá đăng nhập</label>
                            <input class=""form-control"" name=""GiaDN""");
                EndContext();
                BeginWriteAttribute("placeholder", " placeholder=\"", 1983, "\"", 1997, 0);
                EndWriteAttribute();
                BeginWriteAttribute("value", "value=\"", 1998, "\"", 2022, 1);
#line 48 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditSanPhamChild.cshtml"
WriteAttributeValue("", 2005, Model.PriceLogin, 2005, 17, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(2023, 784, true);
                WriteLiteral(@">
                        </div>
                    </div>
                    <div class=""col-sm-2"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label""></label>
                            <div>
                                <button type=""submit"" class=""btn btn-primary"" name=""searchKH"" value=""searchBtn"">Lưu</button>
                            </div>
                        </div>
                    </div>
                    <div class=""col-sm-6"">
                        <div class=""item form-group"">
                            <label class=""control-label col-xs-12"">
                                Hình đại diện
                            </label>
                            <img");
                EndContext();
                BeginWriteAttribute("src", " src=\"", 2807, "\"", 2828, 1);
#line 64 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditSanPhamChild.cshtml"
WriteAttributeValue("", 2813, Model.ChildImg, 2813, 15, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(2829, 187, true);
                WriteLiteral(" style=\"width:100px!important; height:auto;\" alt=\"hình đại diện\" />\r\n                            <input type=\"file\" class=\"form-control-file btn btn-primary\" name=\"files\" accept=\"image/*\"");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 3016, "\"", 3024, 0);
                EndWriteAttribute();
                BeginContext(3025, 69, true);
                WriteLiteral(" />\r\n                            <input type=\"hidden\" name=\"ChildImg\"");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 3094, "\"", 3117, 1);
#line 66 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditSanPhamChild.cshtml"
WriteAttributeValue("", 3102, Model.ChildImg, 3102, 15, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(3118, 331, true);
                WriteLiteral(@" />
                        </div>
                    </div>
                    <div class=""col-sm-6"">
                        <div class=""form-group"">
                            <label for=""inputEmail3"" class=""control-label"">ID Sản phẩm cha</label>
                            <input class=""form-control"" name=""ID_Parent""");
                EndContext();
                BeginWriteAttribute("placeholder", " placeholder=\"", 3449, "\"", 3463, 0);
                EndWriteAttribute();
                BeginWriteAttribute("value", " value=\"", 3464, "\"", 3487, 1);
#line 72 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\EditSanPhamChild.cshtml"
WriteAttributeValue("", 3472, Model.IDParent, 3472, 15, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(3488, 99, true);
                WriteLiteral(">\r\n                        </div>\r\n                    </div>\r\n                </div>\r\n            ");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.RenderAtEndOfFormTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_RenderAtEndOfFormTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Controller = (string)__tagHelperAttribute_0.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_0);
            if (__Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.RouteValues == null)
            {
                throw new InvalidOperationException(InvalidTagHelperIndexerAssignment("asp-route-i", "Microsoft.AspNetCore.Mvc.TagHelpers.FormTagHelper", "RouteValues"));
            }
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.RouteValues["i"] = (string)__tagHelperAttribute_1.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_1);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Action = (string)__tagHelperAttribute_2.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_2);
            __Microsoft_AspNetCore_Mvc_TagHelpers_FormTagHelper.Method = (string)__tagHelperAttribute_3.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_3);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_4);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(3594, 36, true);
            WriteLiteral("\r\n        </div>\r\n    </div>\r\n</div>");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Models.SanPhamChild> Html { get; private set; }
    }
}
#pragma warning restore 1591
