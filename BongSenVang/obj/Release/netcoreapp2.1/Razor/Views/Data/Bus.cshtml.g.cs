#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\Bus.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "9ed88b09563d90d10185797cae6f592a4e997d0c"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Data_Bus), @"mvc.1.0.view", @"/Views/Data/Bus.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Data/Bus.cshtml", typeof(AspNetCore.Views_Data_Bus))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"9ed88b09563d90d10185797cae6f592a4e997d0c", @"/Views/Data/Bus.cshtml")]
    public class Views_Data_Bus : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<List<BongSenVang.Models.BusModel>>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/js/jquery.1.7.2.min.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/js/jquery-ui.1.8.9.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_2 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("href", new global::Microsoft.AspNetCore.Html.HtmlString("~/js/jquery-ui.1.8.9.css"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_3 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("rel", new global::Microsoft.AspNetCore.Html.HtmlString("stylesheet"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
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
#line 2 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\Bus.cshtml"
  
    ViewData["Title"] = "Bus";
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(133, 860, true);
            WriteLiteral(@"
<title>Bus</title>
<div class=""x_panel"">
    <div class=""x_content"">
        <div class=""row"">
            <div class=""col-sm-12"">
                <div>
                    <h2>Tuyến xe bus</h2>
                    <a id=""BtnCreateBus"" data-toggle=""modal"" data-target=""#openPopup"" href=""javascript:;"" class=""btn btn-primary"">Tạo mới</a>
                </div>
                <div class=""table-responsive"">
                    <table id=""gridBus"" class=""table table-hover table-bordered"">
                        <thead>
                            <tr>
                                <th></th>
                                <th>STT</th>
                                <th>Tiêu đề</th>
                                <th>Sân bay</th>
                            </tr>
                        </thead>
                        <tbody>
");
            EndContext();
#line 27 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\Bus.cshtml"
                             if (Model != null)
                            {
                                int i = 1;
                                foreach (var item in Model)
                                {

#line default
#line hidden
            BeginContext(1213, 39, true);
            WriteLiteral("                                    <tr");
            EndContext();
            BeginWriteAttribute("id", " id=\"", 1252, "\"", 1265, 1);
#line 32 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\Bus.cshtml"
WriteAttributeValue("", 1257, item.ID, 1257, 8, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1266, 287, true);
            WriteLiteral(@">
                                        <td style=""text-align: center;""><a class=""Edit"" style=""color:blue;"" data-toggle=""modal"" data-target=""#openPopup"" href=""javascript:;""><i class=""fa fa-pencil-square-o"" aria-hidden=""true""></i></a></td>
                                        <td>");
            EndContext();
            BeginContext(1554, 1, false);
#line 34 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\Bus.cshtml"
                                       Write(i);

#line default
#line hidden
            EndContext();
            BeginContext(1555, 51, true);
            WriteLiteral("</td>\r\n                                        <td>");
            EndContext();
            BeginContext(1607, 11, false);
#line 35 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\Bus.cshtml"
                                       Write(item.TieuDe);

#line default
#line hidden
            EndContext();
            BeginContext(1618, 51, true);
            WriteLiteral("</td>\r\n                                        <td>");
            EndContext();
            BeginContext(1670, 16, false);
#line 36 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\Bus.cshtml"
                                       Write(item.AirportName);

#line default
#line hidden
            EndContext();
            BeginContext(1686, 50, true);
            WriteLiteral("</td>\r\n                                    </tr>\r\n");
            EndContext();
#line 38 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Data\Bus.cshtml"
                                    i++;
                                }
                            }

#line default
#line hidden
            BeginContext(1844, 209, true);
            WriteLiteral("                        </tbody>\r\n                    </table>\r\n                </div>\r\n            </div>\r\n        </div>\r\n    </div>\r\n</div>\r\n\r\n<div class=\"modal fade\" id=\"openPopup\" role=\"dialog\">\r\n</div>\r\n");
            EndContext();
            BeginContext(2053, 48, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "9ed88b09563d90d10185797cae6f592a4e997d0c8202", async() => {
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
            BeginContext(2101, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(2103, 47, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "9ed88b09563d90d10185797cae6f592a4e997d0c9381", async() => {
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
            BeginContext(2150, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(2152, 57, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("link", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.SelfClosing, "9ed88b09563d90d10185797cae6f592a4e997d0c10560", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_2);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_3);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(2209, 1175, true);
            WriteLiteral(@"
<script>
    $(""#gridBus .Edit"").click(function () {
        var id = String($(this).closest('tr').attr('id'));
        $.ajax({
            type: ""POST"",
            url: ""/Data/EditBus"",
            data: {
                ID: id
            },
            success: function (response) {
                $('#openPopup').html(response);
                $('#openPopup').modal('show');
            },
            failure: function (response) {
                alert(response.responseText);
            },
            error: function (response) {
                alert(response.responseText);
            }
        });
    });
    $(""#BtnCreateBus"").click(function () {
        $.ajax({
            type: ""POST"",
            url: ""/Data/CreateBus"",
            success: function (response) {
                $('#openPopup').html(response);
                $('#openPopup').modal('show');
            },
            failure: function (response) {
                alert(response.responseText);
  ");
            WriteLiteral("          },\r\n            error: function (response) {\r\n                alert(response.responseText);\r\n            }\r\n        });\r\n    });\r\n</script>\r\n");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<List<BongSenVang.Models.BusModel>> Html { get; private set; }
    }
}
#pragma warning restore 1591
