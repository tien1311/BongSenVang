#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "1f17e4465afe2917ac022c4eed195c5b52bbc7f1"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_KinhDoanh_DaiLy), @"mvc.1.0.view", @"/Views/KinhDoanh/DaiLy.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/KinhDoanh/DaiLy.cshtml", typeof(AspNetCore.Views_KinhDoanh_DaiLy))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"1f17e4465afe2917ac022c4eed195c5b52bbc7f1", @"/Views/KinhDoanh/DaiLy.cshtml")]
    public class Views_KinhDoanh_DaiLy : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.DanhSachDaiLy>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("href", new global::Microsoft.AspNetCore.Html.HtmlString("~/jquery.dataTables.css"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("rel", new global::Microsoft.AspNetCore.Html.HtmlString("stylesheet"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_2 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/js/jquery.1.7.2.min.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_3 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/js/jquery-ui.1.8.9.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_4 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("href", new global::Microsoft.AspNetCore.Html.HtmlString("~/js/jquery-ui.1.8.9.css"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
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
            BeginContext(41, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 3 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
  
    var acc = ViewBag.ACC;
    ViewData["Title"] = "Danh sách đại lý";
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(175, 7, true);
            WriteLiteral("<title>");
            EndContext();
            BeginContext(183, 17, false);
#line 8 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
  Write(ViewData["Title"]);

#line default
#line hidden
            EndContext();
            BeginContext(200, 10, true);
            WriteLiteral("</title>\r\n");
            EndContext();
            BeginContext(210, 56, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("link", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.SelfClosing, "1f17e4465afe2917ac022c4eed195c5b52bbc7f15335", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_0);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_1);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(266, 443, true);
            WriteLiteral(@"
<h2 style=""text-align: center; font-weight: bold;"">DANH SÁCH ĐẠI LÝ </h2>
<br />
<style>

    a.paginate_button.current {
        background: #2A3F54 !important;
        color: #fff !important;
    }

    a.paginate_button:hover {
        background: #2A3F54 !important;
    }

    .form-group {
        margin-bottom: 15px;
    }
</style>
<div class=""x_panel"" style=""padding: 10px 17px 0;"">

    <div class=""x_content"">
");
            EndContext();
#line 30 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
         using (Html.BeginForm("SearchDaiLy", "KinhDoanh", new { i = 10 }, FormMethod.Post))
        {

#line default
#line hidden
            BeginContext(814, 415, true);
            WriteLiteral(@"            <div class=""row"">
                <div class=""col-md-2 col-xs-12"">
                    <div class=""form-group"">

                        <button type=""submit"" name=""search_ALL"" value=""ALL"" class=""btn btn-warning"" style="" background-color: #f4811f;"">Danh sách đại lý</button>
                    </div>
                </div>
            </div>
            <div class=""row"">
                <div");
            EndContext();
            BeginWriteAttribute("class", " class=\"", 1229, "\"", 1237, 0);
            EndWriteAttribute();
            BeginContext(1238, 5, true);
            WriteLiteral(">\r\n\r\n");
            EndContext();
#line 43 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                     if (acc == "NV00293" || acc == "NV00016" || acc == "" || acc == "NV00006" || acc == "NV00001")
                    {

#line default
#line hidden
            BeginContext(1383, 189, true);
            WriteLiteral("                        <div class=\"col-md-2 col-xs-12\">\r\n                            <div class=\"form-group\">\r\n\r\n                                <select name=\"MaNV\" class=\"form-control\">\r\n");
            EndContext();
#line 49 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                     foreach (var item in Model.ListKinhDoanh)
                                    {

#line default
#line hidden
            BeginContext(1691, 47, true);
            WriteLiteral("                                        <option");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1738, "\"", 1756, 1);
#line 51 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
WriteAttributeValue("", 1746, item.MaNV, 1746, 10, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1757, 47, true);
            WriteLiteral(">\r\n                                            ");
            EndContext();
            BeginContext(1805, 10, false);
#line 52 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                       Write(item.TenNV);

#line default
#line hidden
            EndContext();
            BeginContext(1815, 53, true);
            WriteLiteral("\r\n                                        </option>\r\n");
            EndContext();
#line 54 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                    }

#line default
#line hidden
            BeginContext(1907, 113, true);
            WriteLiteral("                                </select>\r\n\r\n                            </div>\r\n                        </div>\r\n");
            EndContext();
#line 59 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                    }

#line default
#line hidden
            BeginContext(2043, 1031, true);
            WriteLiteral(@"
                    <div class=""col-md-2 col-xs-12"">
                        <div class=""form-group"">

                            <select name=""DieuKien"" class=""form-control"">
                                <option value=""0"">Mã KH</option>
                                <option value=""1"">Sign in</option>
                            </select>
                        </div>
                    </div>
                    <div class=""col-md-2 col-xs-12"">
                        <div class=""form-group"">

                            <input class=""form-control"" type=""text"" name=""GiaTri"" />
                        </div>
                    </div>
                    <div class=""col-md-1 col-xs-12"">
                        <div class=""form-group"" style=""text-align:right;"">

                            <button type=""submit"" name=""search_KH"" value=""search"" class=""btn btn-primary"">Tìm kiếm</button>
                        </div>
                    </div>

                </div>
            <");
            WriteLiteral("/div>\r\n");
            EndContext();
#line 85 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
        }

#line default
#line hidden
            BeginContext(3085, 1156, true);
            WriteLiteral(@"    </div>
</div>
<div class=""x_panel"">
    <div class=""x_content"">
        <div class=""row"">
            <div class=""table-responsive"">
                <table id=""gridTaiKhoanDaiLy"" class=""table table-hover table-bordered"">
                    <thead>
                        <tr>
                            <th style=""text-align:center"">STT</th>
                            <th style=""text-align:center"">Mã KH</th>
                            <th>Tên Đại Lý</th>
                            <th style=""text-align:right"">Số Dư</th>
                            <th style=""text-align:center"">Hạng</th>
                            <th style=""text-align:right"">Cho xuất</th>
                            <th style=""text-align:center"">Signin</th>
                            <th style=""text-align:center"">Kế toán</th>
                            <th style=""width: 165px; text-align: center"">Note KT</th>
                            <th style=""text-align:center"">Tình trạng</th>
                            <th");
            WriteLiteral(" style=\"text-align:center\">Doanh số</th>\r\n                        </tr>\r\n                    </thead>\r\n                    <tbody>\r\n");
            EndContext();
#line 109 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                         if (Model.ListDaiLy != null)
                        {
                            int i = 1;
                            foreach (var item in Model.ListDaiLy)
                            {
                                double sodu = 0;
                                if (item.SoDu != "")
                                {
                                    sodu = double.Parse(item.SoDu);
                                }


#line default
#line hidden
            BeginContext(4706, 35, true);
            WriteLiteral("                                <tr");
            EndContext();
            BeginWriteAttribute("id", " id=\"", 4741, "\"", 4761, 1);
#line 120 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
WriteAttributeValue("", 4746, item.member_kh, 4746, 15, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginWriteAttribute("class", " class=\"", 4762, "\"", 4770, 0);
            EndWriteAttribute();
            BeginContext(4771, 69, true);
            WriteLiteral(">\r\n                                    <td style=\"text-align:center\">");
            EndContext();
            BeginContext(4841, 1, false);
#line 121 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                                             Write(i);

#line default
#line hidden
            EndContext();
            BeginContext(4842, 73, true);
            WriteLiteral("</td>\r\n                                    <td style=\"text-align:center\">");
            EndContext();
            BeginContext(4916, 14, false);
#line 122 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                                             Write(item.member_kh);

#line default
#line hidden
            EndContext();
            BeginContext(4930, 47, true);
            WriteLiteral("</td>\r\n                                    <td>");
            EndContext();
            BeginContext(4978, 19, false);
#line 123 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                   Write(item.member_company);

#line default
#line hidden
            EndContext();
            BeginContext(4997, 9, true);
            WriteLiteral("</td>\r\n\r\n");
            EndContext();
#line 125 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                     if (@item.SoDu != "")
                                    {
                                        

#line default
#line hidden
#line 127 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                         if (sodu > 0)
                                        {

#line default
#line hidden
            BeginContext(5204, 87, true);
            WriteLiteral("                                            <td style=\"color: blue; text-align: right\">");
            EndContext();
            BeginContext(5292, 9, false);
#line 129 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                                                                  Write(item.SoDu);

#line default
#line hidden
            EndContext();
            BeginContext(5301, 7, true);
            WriteLiteral("</td>\r\n");
            EndContext();
#line 130 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                        }
                                        else
                                        {

#line default
#line hidden
            BeginContext(5440, 87, true);
            WriteLiteral("                                            <td style=\"color: red; text-align: right \">");
            EndContext();
            BeginContext(5528, 9, false);
#line 133 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                                                                  Write(item.SoDu);

#line default
#line hidden
            EndContext();
            BeginContext(5537, 7, true);
            WriteLiteral("</td>\r\n");
            EndContext();
#line 134 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"

                                        }

#line default
#line hidden
#line 135 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                         
                                    }
                                    else
                                    {

#line default
#line hidden
            BeginContext(5709, 90, true);
            WriteLiteral("                                        <td style=\"color: red; text-align: right\">0</td>\r\n");
            EndContext();
#line 140 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                    }

#line default
#line hidden
            BeginContext(5838, 66, true);
            WriteLiteral("                                    <td style=\"text-align:center\">");
            EndContext();
            BeginContext(5905, 9, false);
#line 141 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                                             Write(item.Hang);

#line default
#line hidden
            EndContext();
            BeginContext(5914, 7, true);
            WriteLiteral("</td>\r\n");
            EndContext();
#line 142 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                     if (@item.AmQuyChoPhep != "")
                                    {

#line default
#line hidden
            BeginContext(6028, 69, true);
            WriteLiteral("                                        <td style=\"text-align:right\">");
            EndContext();
            BeginContext(6098, 17, false);
#line 144 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                                                Write(item.AmQuyChoPhep);

#line default
#line hidden
            EndContext();
            BeginContext(6115, 7, true);
            WriteLiteral("</td>\r\n");
            EndContext();
#line 145 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                    }
                                    else
                                    {

#line default
#line hidden
            BeginContext(6242, 77, true);
            WriteLiteral("                                        <td style=\"text-align:right\">0</td>\r\n");
            EndContext();
#line 149 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                    }

#line default
#line hidden
            BeginContext(6358, 153, true);
            WriteLiteral("\r\n                                    <td style=\"text-align:center\"><a class=\"DSdaily\" data-toggle=\"modal\" data-target=\"#openPopup\" href=\"javascript:;\"> ");
            EndContext();
            BeginContext(6512, 15, false);
#line 151 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                                                                                                                                  Write(item.CodeSignIn);

#line default
#line hidden
            EndContext();
            BeginContext(6527, 78, true);
            WriteLiteral(" </a></td>\r\n                                    <td style=\"text-align:center\">");
            EndContext();
            BeginContext(6606, 13, false);
#line 152 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                                             Write(item.KeToanEV);

#line default
#line hidden
            EndContext();
            BeginContext(6619, 73, true);
            WriteLiteral("</td>\r\n                                    <td style=\"text-align:center\">");
            EndContext();
            BeginContext(6693, 15, false);
#line 153 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                                             Write(item.NoteKeToan);

#line default
#line hidden
            EndContext();
            BeginContext(6708, 73, true);
            WriteLiteral("</td>\r\n                                    <td style=\"text-align:center\">");
            EndContext();
            BeginContext(6782, 14, false);
#line 154 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                                             Write(item.tinhtrang);

#line default
#line hidden
            EndContext();
            BeginContext(6796, 210, true);
            WriteLiteral("</td>\r\n                                    <td style=\"text-align:center\"><a class=\"Doanhso\" data-toggle=\"modal\" data-target=\"#openPopup\" href=\"javascript:;\">Xem</a></td>\r\n                                </tr>\r\n");
            EndContext();
#line 157 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                i++;
                            }
                        }

#line default
#line hidden
#line 160 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                         if (Model.ThongBao != null && Model.ThongBao != "")
                        {

#line default
#line hidden
            BeginContext(7207, 122, true);
            WriteLiteral("                            <tr>\r\n                                <td colspan=\"9\" style=\"text-align: center; color: red;\">");
            EndContext();
            BeginContext(7330, 14, false);
#line 163 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"
                                                                                   Write(Model.ThongBao);

#line default
#line hidden
            EndContext();
            BeginContext(7344, 42, true);
            WriteLiteral("</td>\r\n                            </tr>\r\n");
            EndContext();
#line 165 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KinhDoanh\DaiLy.cshtml"

                        }

#line default
#line hidden
            BeginContext(7415, 179, true);
            WriteLiteral("\r\n                    </tbody>\r\n                </table>\r\n            </div>\r\n        </div>\r\n    </div>\r\n</div>\r\n<div class=\"modal fade\" id=\"openPopup\" role=\"dialog\">\r\n</div>\r\n\r\n");
            EndContext();
            BeginContext(7594, 48, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "1f17e4465afe2917ac022c4eed195c5b52bbc7f123927", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_2);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(7642, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(7644, 47, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "1f17e4465afe2917ac022c4eed195c5b52bbc7f125107", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_3);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(7691, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(7693, 57, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("link", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.SelfClosing, "1f17e4465afe2917ac022c4eed195c5b52bbc7f126287", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_4);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_1);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(7750, 1850, true);
            WriteLiteral(@"

<script type=""text/javascript"">
    $(""#gridTaiKhoanDaiLy .DSdaily"").click(function () {
        var subject_id = String($(this).closest('tr').attr('id'));
        $.ajax({
            type: ""POST"",

            url: ""/KinhDoanh/ThongTinCodeSignIn"",
            data: { khoachinh: subject_id },
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

    $(""#gridTaiKhoanDaiLy .Doanhso"").click(function () {
        var subject_id = String($(this).closest('tr').attr('id'));
        $.ajax({
            type: ""POST"",

            url: ""/KinhDoanh/ThongTinDoanhSo"",
            data: { MaKH: subject_id },
            success: function (response) {
                $('");
            WriteLiteral(@"#openPopup').html(response);
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
</script>
<script>
    $(document).ready(function () {
        var TaiKhoanDaiLy = document.getElementById(""gridTaiKhoanDaiLy"");
        var lengthTaiKhoan = TaiKhoanDaiLy.rows.length;

        if (lengthTaiKhoan > 2) {
            $('#gridTaiKhoanDaiLy').dataTable({
                ""pageLength"": 50,
                ""language"": {
                    url: 'http://cdn.datatables.net/plug-ins/1.10.21/i18n/Vietnamese.json'
                }
            });
        }
    });
</script>");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Models.DanhSachDaiLy> Html { get; private set; }
    }
}
#pragma warning restore 1591
