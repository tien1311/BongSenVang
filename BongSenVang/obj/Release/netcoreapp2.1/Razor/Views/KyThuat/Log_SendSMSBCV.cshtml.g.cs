#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "aabe22784620f75776da09ada8a3763e0759bcf1"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_KyThuat_Log_SendSMSBCV), @"mvc.1.0.view", @"/Views/KyThuat/Log_SendSMSBCV.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/KyThuat/Log_SendSMSBCV.cshtml", typeof(AspNetCore.Views_KyThuat_Log_SendSMSBCV))]
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
#line 3 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
using ReflectionIT.Mvc.Paging;

#line default
#line hidden
#line 4 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
using Microsoft.AspNetCore.Http;

#line default
#line hidden
#line 7 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
using Microsoft.AspNetCore.Html;

#line default
#line hidden
#line 8 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
using BongSenVang.Models.Repository;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"aabe22784620f75776da09ada8a3763e0759bcf1", @"/Views/KyThuat/Log_SendSMSBCV.cshtml")]
    public class Views_KyThuat_Log_SendSMSBCV : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<PagingList<BongSenVang.Models.LOG_SendSMSBaoCaoVe>>
    {
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
        private global::AspNetCore.Views_KyThuat_Log_SendSMSBCV.__Generated__PagerViewComponentTagHelper __PagerViewComponentTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(0, 4, true);
            WriteLiteral("\r\n\r\n");
            EndContext();
            BeginContext(245, 4, true);
            WriteLiteral("\r\n\r\n");
            EndContext();
#line 11 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
  
    ViewData["Title"] = "Log_SendSMSBCV";
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(351, 7, true);
            WriteLiteral("<title>");
            EndContext();
            BeginContext(359, 17, false);
#line 15 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
  Write(ViewData["Title"]);

#line default
#line hidden
            EndContext();
            BeginContext(376, 627, true);
            WriteLiteral(@"</title>
<h2>Log gửi SMS báo cáo vé</h2>
<div class=""x_panel"">
    <div class=""x_content"">
        <div class=""table-responsive"" style=""font-size:12px;"">
            <table id=""gridTable"" class=""table table-striped jambo_table bulk_action"">
                <thead>
                    <tr>
                        <th>STT</th>
                        <th>Mã NV</th>
                        <th>SDT Nhận</th>
                        <th>Nội dung</th>
                        <th>Người gửi</th>
                        <th>Ngày gửi</th>
                    </tr>
                </thead>
                <tbody>
");
            EndContext();
#line 32 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
                     if (Model != null)
                    {
                        int i = 1;
                        foreach (var item in Model)
                        {

#line default
#line hidden
            BeginContext(1183, 70, true);
            WriteLiteral("                            <tr>\r\n                                <td>");
            EndContext();
            BeginContext(1254, 1, false);
#line 38 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
                               Write(i);

#line default
#line hidden
            EndContext();
            BeginContext(1255, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(1299, 9, false);
#line 39 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
                               Write(item.MANV);

#line default
#line hidden
            EndContext();
            BeginContext(1308, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(1352, 14, false);
#line 40 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
                               Write(item.DIENTHOAI);

#line default
#line hidden
            EndContext();
            BeginContext(1366, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(1410, 16, false);
#line 41 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
                               Write(item.NOIDUNG_SMS);

#line default
#line hidden
            EndContext();
            BeginContext(1426, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(1470, 13, false);
#line 42 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
                               Write(item.NGUOIGUI);

#line default
#line hidden
            EndContext();
            BeginContext(1483, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(1527, 12, false);
#line 43 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
                               Write(item.NGAYGUI);

#line default
#line hidden
            EndContext();
            BeginContext(1539, 42, true);
            WriteLiteral("</td>\r\n                            </tr>\r\n");
            EndContext();
#line 45 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
                            i++;
                        }
                    }

#line default
#line hidden
            BeginContext(1665, 126, true);
            WriteLiteral("\r\n                </tbody>\r\n            </table>\r\n        </div>\r\n        <div class=\"row\" style=\"float:right;\">\r\n            ");
            EndContext();
            BeginContext(1791, 42, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("vc:pager", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "aabe22784620f75776da09ada8a3763e0759bcf18200", async() => {
            }
            );
            __PagerViewComponentTagHelper = CreateTagHelper<global::AspNetCore.Views_KyThuat_Log_SendSMSBCV.__Generated__PagerViewComponentTagHelper>();
            __tagHelperExecutionContext.Add(__PagerViewComponentTagHelper);
#line 53 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Log_SendSMSBCV.cshtml"
__PagerViewComponentTagHelper.pagingList = Model;

#line default
#line hidden
            __tagHelperExecutionContext.AddTagHelperAttribute("paging-list", __PagerViewComponentTagHelper.pagingList, global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(1833, 40, true);
            WriteLiteral("\r\n        </div>\r\n    </div>\r\n</div>\r\n\r\n");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<PagingList<BongSenVang.Models.LOG_SendSMSBaoCaoVe>> Html { get; private set; }
        [Microsoft.AspNetCore.Razor.TagHelpers.HtmlTargetElementAttribute("vc:pager")]
        public class __Generated__PagerViewComponentTagHelper : Microsoft.AspNetCore.Razor.TagHelpers.TagHelper
        {
            private readonly global::Microsoft.AspNetCore.Mvc.IViewComponentHelper _helper = null;
            public __Generated__PagerViewComponentTagHelper(global::Microsoft.AspNetCore.Mvc.IViewComponentHelper helper)
            {
                _helper = helper;
            }
            [Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeNotBoundAttribute, global::Microsoft.AspNetCore.Mvc.ViewFeatures.ViewContextAttribute]
            public global::Microsoft.AspNetCore.Mvc.Rendering.ViewContext ViewContext { get; set; }
            public ReflectionIT.Mvc.Paging.IPagingList pagingList { get; set; }
            public override async global::System.Threading.Tasks.Task ProcessAsync(Microsoft.AspNetCore.Razor.TagHelpers.TagHelperContext context, Microsoft.AspNetCore.Razor.TagHelpers.TagHelperOutput output)
            {
                (_helper as global::Microsoft.AspNetCore.Mvc.ViewFeatures.IViewContextAware)?.Contextualize(ViewContext);
                var content = await _helper.InvokeAsync("Pager", new { pagingList });
                output.TagName = null;
                output.Content.SetHtmlContent(content);
            }
        }
    }
}
#pragma warning restore 1591
