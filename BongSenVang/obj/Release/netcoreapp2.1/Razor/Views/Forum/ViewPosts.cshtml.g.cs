#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "eafc5a66b02bb1e64842403391b3ed19c4674d50"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Forum_ViewPosts), @"mvc.1.0.view", @"/Views/Forum/ViewPosts.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Forum/ViewPosts.cshtml", typeof(AspNetCore.Views_Forum_ViewPosts))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"eafc5a66b02bb1e64842403391b3ed19c4674d50", @"/Views/Forum/ViewPosts.cshtml")]
    public class Views_Forum_ViewPosts : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.PostForumModel>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(42, 15, true);
            WriteLiteral("\r\n<style>\r\n    ");
            EndContext();
            BeginContext(58, 1112, true);
            WriteLiteral(@"@media(min-width: 768px) {
        .modal-dialog {
            width: 1000px;
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

    .category {
        -moz-border-radius: 2px;
        -webkit-border-radius: 2px;
        display: block;
        float: left;
        padding: 5px 9px;
        background: #3ebafa;
        color: #F1F6F7;
        margin-right: 5px;
        font-weight: 500;
        margin-bottom: 5px;
        font-family: helvetica;
        line-height: 1;
    }
</style>
<div class=""modal-dialog"">
    <!-- Modal content-->
    <div class=""modal-content"" style="" background: #2A3F54;"">
        <div class=""modal-header"">
            <button type=""button"" class=""close"" data-dismiss=""modal"">&times;</button>
            <h1 style=""color: #FFF; font-size: 16px;"">Duyệt bài viết</h1>
        </di");
            WriteLiteral("v>\r\n        <div class=\"modal-body\" style=\"border-radius:8px; background-color:#fff;\">\r\n");
            EndContext();
#line 44 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
             using (Html.BeginForm("ConfirmPost", "Forum", new { i = 9 }, FormMethod.Post))
            {

#line default
#line hidden
            BeginContext(1278, 45, true);
            WriteLiteral("                <div style=\"font-size:18px;\">");
            EndContext();
            BeginContext(1324, 11, false);
#line 46 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                        Write(Model.Title);

#line default
#line hidden
            EndContext();
            BeginContext(1335, 54, true);
            WriteLiteral("</div>\r\n                <input type=\"hidden\" name=\"ID\"");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1389, "\"", 1406, 1);
#line 47 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
WriteAttributeValue("", 1397, Model.Id, 1397, 9, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1407, 71, true);
            WriteLiteral(" />\r\n                <div>\r\n                    <span class=\"category\">");
            EndContext();
            BeginContext(1479, 14, false);
#line 49 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                      Write(Model.Category);

#line default
#line hidden
            EndContext();
            BeginContext(1493, 9, true);
            WriteLiteral("</span>\r\n");
            EndContext();
#line 50 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                     foreach (var item in Model.ListTags)
                    {

#line default
#line hidden
            BeginContext(1584, 42, true);
            WriteLiteral("                        <span class=\"tag\">");
            EndContext();
            BeginContext(1627, 9, false);
#line 52 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                     Write(item.Name);

#line default
#line hidden
            EndContext();
            BeginContext(1636, 9, true);
            WriteLiteral("</span>\r\n");
            EndContext();
#line 53 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                    }

#line default
#line hidden
            BeginContext(1668, 134, true);
            WriteLiteral("                </div>\r\n                <div class=\"clear\"></div>\r\n                <hr />\r\n                <div>\r\n                    ");
            EndContext();
            BeginContext(1803, 27, false);
#line 58 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
               Write(Html.Raw(Model.Description));

#line default
#line hidden
            EndContext();
            BeginContext(1830, 616, true);
            WriteLiteral(@"
                </div>
                <hr />
                <label class=""col-form-label pad-top-6 col-md-1 col-sm-2 col-xs-3 label-align"">
                    Tình trạng
                </label>
                <div class=""col-xs-3"">
                    <fieldset class=""col-xs-12"" style=""padding:0px"">
                        <div class=""control-group"">
                            <div class=""controls"">
                                <div class="" xdisplay_inputx form-group has-feedback"">
                                    <select id=""Status"" name=""Status"" class=""select2_single form-control"">
");
            EndContext();
#line 70 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                         if (Model.Status == "0")
                                        {

#line default
#line hidden
            BeginContext(2556, 335, true);
            WriteLiteral(@"                                            <option selected value=""0"">Đã xóa</option>
                                            <option value=""1"">Đã đăng</option>
                                            <option value=""2"">Không duyệt</option>
                                            <option value=""3"">Chưa duyệt</option>
");
            EndContext();
#line 76 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                        }

#line default
#line hidden
#line 77 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                         if (Model.Status == "1")
                                        {

#line default
#line hidden
            BeginContext(3044, 335, true);
            WriteLiteral(@"                                            <option value=""0"">Đã xóa</option>
                                            <option selected value=""1"">Đã đăng</option>
                                            <option value=""2"">Không duyệt</option>
                                            <option value=""3"">Chưa duyệt</option>
");
            EndContext();
#line 83 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                        }

#line default
#line hidden
#line 84 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                         if (Model.Status == "2")
                                        {

#line default
#line hidden
            BeginContext(3532, 335, true);
            WriteLiteral(@"                                            <option value=""0"">Đã xóa</option>
                                            <option value=""1"">Đã đăng</option>
                                            <option selected value=""2"">Không duyệt</option>
                                            <option value=""3"">Chưa duyệt</option>
");
            EndContext();
#line 90 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                        }

#line default
#line hidden
#line 91 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                         if (Model.Status == "3")
                                        {

#line default
#line hidden
            BeginContext(4020, 335, true);
            WriteLiteral(@"                                            <option value=""0"">Đã xóa</option>
                                            <option value=""1"">Đã đăng</option>
                                            <option value=""2"">Không duyệt</option>
                                            <option selected value=""3"">Chưa duyệt</option>
");
            EndContext();
#line 97 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                        }

#line default
#line hidden
            BeginContext(4398, 516, true);
            WriteLiteral(@"                                    </select>
                                </div>
                            </div>
                        </div>
                    </fieldset>
                </div>
                <div class=""item form-group col-xs-3"">
                    <input type=""submit"" class=""btn btn-primary"" name=""btnStatus"" value=""Save"">
                </div>
                <div>
                    <textarea class=""form-control"" name=""Note"" placeholder=""Lý do không duyệt"" rows=""3"">");
            EndContext();
            BeginContext(4915, 10, false);
#line 108 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
                                                                                                   Write(Model.Note);

#line default
#line hidden
            EndContext();
            BeginContext(4925, 37, true);
            WriteLiteral("</textarea>\r\n                </div>\r\n");
            EndContext();
#line 110 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Forum\ViewPosts.cshtml"
            }

#line default
#line hidden
            BeginContext(4977, 34, true);
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Models.PostForumModel> Html { get; private set; }
    }
}
#pragma warning restore 1591
