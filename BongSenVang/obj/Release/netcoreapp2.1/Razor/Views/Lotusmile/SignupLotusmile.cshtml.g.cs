#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "d85967805de67d062132e7f5181e92394bc0c969"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Lotusmile_SignupLotusmile), @"mvc.1.0.view", @"/Views/Lotusmile/SignupLotusmile.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Lotusmile/SignupLotusmile.cshtml", typeof(AspNetCore.Views_Lotusmile_SignupLotusmile))]
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
#line 1 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
using BongSenVang.Models;

#line default
#line hidden
#line 2 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
using BongSenVang.Models.Repository;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"d85967805de67d062132e7f5181e92394bc0c969", @"/Views/Lotusmile/SignupLotusmile.cshtml")]
    public class Views_Lotusmile_SignupLotusmile : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("rel", new global::Microsoft.AspNetCore.Html.HtmlString("stylesheet"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("href", new global::Microsoft.AspNetCore.Html.HtmlString("~/vendors/BSV/bootstrap/css/bootstrap.min.css"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_2 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("type", new global::Microsoft.AspNetCore.Html.HtmlString("text/javascript"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_3 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/vendors/BSV/bootstrap/js/bootstrap.min.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_4 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("class", new global::Microsoft.AspNetCore.Html.HtmlString("logo"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_5 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/images/logoVN.png"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
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
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.HeadTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_HeadTagHelper;
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper;
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.BodyTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_BodyTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#line 3 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
  
    LotusmileRepository Lotus_Rep = new LotusmileRepository();
    var Content_Right = Lotus_Rep.Content_Right();

#line default
#line hidden
            BeginContext(190, 25, true);
            WriteLiteral("<!DOCTYPE html>\r\n<html>\r\n");
            EndContext();
            BeginContext(215, 2077, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("head", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "d85967805de67d062132e7f5181e92394bc0c9695944", async() => {
                BeginContext(221, 174, true);
                WriteLiteral("\r\n    <meta charset=\"utf-8\">\r\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\r\n    <link rel=\"stylesheet\" type=\"text/css\" href=\"css/mycss.css\">\r\n    ");
                EndContext();
                BeginContext(395, 78, false);
                __tagHelperExecutionContext = __tagHelperScopeManager.Begin("link", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.SelfClosing, "d85967805de67d062132e7f5181e92394bc0c9696517", async() => {
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
                BeginContext(473, 6, true);
                WriteLiteral("\r\n    ");
                EndContext();
                BeginContext(479, 90, false);
                __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "d85967805de67d062132e7f5181e92394bc0c9697849", async() => {
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
                BeginContext(569, 1419, true);
                WriteLiteral(@"
    <title></title>
    <style>
        * {
            box-sizing: border-box;
        }

        body {
            background-image: url(../images/bg_bsv.jpg);
            background-size: cover;
            background-repeat: no-repeat;
            background-position: center;
        }

        .contain-img img {
            width: 100%;
        }

        .contain-body {
            padding: 15px 0;
        }

        .form-label {
            font-weight: bold;
        }

        .form-signup {
            background-color: #fff;
            border-radius: 5px;
            margin: 10px 0px;
            padding-bottom: 30px;
        }

        .form-header {
            background-color: #086d88;
            color: #fff;
            font-size: 18px;
            padding: 5px 16px;
            border-radius: 5px 5px 0 0;
            text-align: center;
        }

            .form-header img {
                width: 25%;
            }

            .form-heade");
                WriteLiteral(@"r p {
                font-size: 26px;
                margin-bottom: 0px;
                line-height: 39px;
                font-family: initial;
            }

        .row {
            padding: 0 15px;
        }

        .form-text {
            padding: 0 15px;
        }

        .d-grid {
            padding: 0 15px;
            margin-top: 15px;
        }

        ");
                EndContext();
                BeginContext(1989, 165, true);
                WriteLiteral("@media (max-width: 991px) {\r\n            .form-header p {\r\n                font-size: 20px;\r\n                line-height: 27px;\r\n            }\r\n        }\r\n\r\n        ");
                EndContext();
                BeginContext(2155, 130, true);
                WriteLiteral("@media (max-width: 767px) {\r\n            .form-header img {\r\n                width: 45%;\r\n            }\r\n        }\r\n    </style>\r\n");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_HeadTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.HeadTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_HeadTagHelper);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(2292, 4, true);
            WriteLiteral("\r\n\r\n");
            EndContext();
            BeginContext(2296, 9463, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("body", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "d85967805de67d062132e7f5181e92394bc0c96911996", async() => {
                BeginContext(2302, 121, true);
                WriteLiteral("\r\n    <div class=\"container\">\r\n        <div class=\"form-signup\">\r\n            <div class=\"form-header\">\r\n                ");
                EndContext();
                BeginContext(2423, 44, false);
                __tagHelperExecutionContext = __tagHelperScopeManager.Begin("img", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagOnly, "d85967805de67d062132e7f5181e92394bc0c96912513", async() => {
                }
                );
                __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
                __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
                __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_4);
                __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_5);
                await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
                if (!__tagHelperExecutionContext.Output.IsContentModified)
                {
                    await __tagHelperExecutionContext.SetOutputContentAsync();
                }
                Write(__tagHelperExecutionContext.Output);
                __tagHelperExecutionContext = __tagHelperScopeManager.End();
                EndContext();
                BeginContext(2467, 114, true);
                WriteLiteral("\r\n                <p>ĐĂNG KÝ HỘI VIÊN LOTUSMILES</p>\r\n            </div>\r\n            <div class=\"contain-body\">\r\n");
                EndContext();
#line 103 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                 using (Html.BeginForm("SignupLotusmile", "Lotusmile", new { i = 12 }, FormMethod.Post))
                {

#line default
#line hidden
                BeginContext(2706, 785, true);
                WriteLiteral(@"                    <div class=""row"">
                        <div class=""col-sm-6"" style=""margin-bottom: 20px;"">
                            <div class=""contain-form"">
                                <p style=""margin-bottom: 0px;font-style: italic;"">Tất cả các trường có dấu <span style=""color: red;font-weight: bold;"">*</span> là bắt buộc</p>
                                <div class=""row"">
                                    <label class=""form-label"">Danh xưng<span style=""color:red;"">*</span></label>
                                    <div class=""mb-1"">
                                        <div class=""col-sm-3"">
                                            <select name=""Title"" class=""form-select"" required>
                                                <option");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 3491, "\"", 3499, 0);
                EndWriteAttribute();
                BeginContext(3500, 1983, true);
                WriteLiteral(@">Chọn</option>
                                                <option value=""Ông"">Ông</option>
                                                <option value=""Bà"">Bà</option>
                                                <option value=""Cô/Chị"">Cô/Chị</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                                <div class=""row"">
                                    <div class=""col-sm-6"">
                                        <div class=""mb-1"">
                                            <label class=""form-label"">Họ<span style=""color:red;"">*</span></label>
                                            <input id=""LastName"" name=""LastName"" type=""text"" class=""form-control"" placeholder=""Họ"" onchange=""xoa_dau(this.id)"" required>
                                        </div>
                                    </div>
                       ");
                WriteLiteral(@"             <div class=""col-sm-6"">
                                        <div class=""mb-1"">
                                            <label class=""form-label"">Đệm và tên<span style=""color:red;"">*</span></label>
                                            <input id=""FirstName"" name=""FirstName"" type=""text"" class=""form-control"" placeholder=""Tên"" onchange=""xoa_dau(this.id)"" required>
                                        </div>
                                    </div>
                                </div>
                                <div class=""row"">
                                    <label class=""form-label"">Ngày sinh<span style=""color:red;"">*</span></label>
                                    <div class=""col-sm-4"">
                                        <div class=""mb-1"">
                                            <select name=""Day"" class=""form-select"" required>
                                                <option");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 5483, "\"", 5491, 0);
                EndWriteAttribute();
                BeginContext(5492, 16, true);
                WriteLiteral(">Ngày</option>\r\n");
                EndContext();
#line 142 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                                                 for (int i = 1; i <= 31; i++)
                                                {

#line default
#line hidden
                BeginContext(5639, 59, true);
                WriteLiteral("                                                    <option");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 5698, "\"", 5708, 1);
#line 144 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
WriteAttributeValue("", 5706, i, 5706, 2, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(5709, 1, true);
                WriteLiteral(">");
                EndContext();
                BeginContext(5711, 1, false);
#line 144 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                                                                  Write(i);

#line default
#line hidden
                EndContext();
                BeginContext(5712, 11, true);
                WriteLiteral("</option>\r\n");
                EndContext();
#line 145 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                                                }

#line default
#line hidden
                BeginContext(5774, 418, true);
                WriteLiteral(@"                                            </select>
                                        </div>
                                    </div>
                                    <div class=""col-sm-4"">
                                        <div class=""mb-1"">
                                            <select name=""Month"" class=""form-select"" required>
                                                <option");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 6192, "\"", 6200, 0);
                EndWriteAttribute();
                BeginContext(6201, 17, true);
                WriteLiteral(">Tháng</option>\r\n");
                EndContext();
#line 153 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                                                 for (int i = 1; i <= 12; i++)
                                                {

#line default
#line hidden
                BeginContext(6349, 59, true);
                WriteLiteral("                                                    <option");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 6408, "\"", 6418, 1);
#line 155 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
WriteAttributeValue("", 6416, i, 6416, 2, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(6419, 1, true);
                WriteLiteral(">");
                EndContext();
                BeginContext(6421, 1, false);
#line 155 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                                                                  Write(i);

#line default
#line hidden
                EndContext();
                BeginContext(6422, 11, true);
                WriteLiteral("</option>\r\n");
                EndContext();
#line 156 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                                                }

#line default
#line hidden
                BeginContext(6484, 417, true);
                WriteLiteral(@"                                            </select>
                                        </div>
                                    </div>
                                    <div class=""col-sm-4"">
                                        <div class=""mb-1"">
                                            <select name=""Year"" class=""form-select"" required>
                                                <option");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 6901, "\"", 6909, 0);
                EndWriteAttribute();
                BeginContext(6910, 15, true);
                WriteLiteral(">Năm</option>\r\n");
                EndContext();
#line 164 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                                                 for (int i = DateTime.Now.Year; i >= 1900; i--)
                                                {

#line default
#line hidden
                BeginContext(7074, 59, true);
                WriteLiteral("                                                    <option");
                EndContext();
                BeginWriteAttribute("value", " value=\"", 7133, "\"", 7143, 1);
#line 166 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
WriteAttributeValue("", 7141, i, 7141, 2, false);

#line default
#line hidden
                EndWriteAttribute();
                BeginContext(7144, 1, true);
                WriteLiteral(">");
                EndContext();
                BeginContext(7146, 1, false);
#line 166 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                                                                  Write(i);

#line default
#line hidden
                EndContext();
                BeginContext(7147, 11, true);
                WriteLiteral("</option>\r\n");
                EndContext();
#line 167 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                                                }

#line default
#line hidden
                BeginContext(7209, 2335, true);
                WriteLiteral(@"                                            </select>
                                        </div>
                                    </div>
                                </div>
                                <div class=""row mb-1"">
                                    <label class=""form-label"">Email<span style=""color:red;"">*</span></label>
                                    <div class=""input-group"">
                                        <input name=""Email"" type=""email"" class=""form-control"" placeholder=""Email"" required>
                                    </div>
                                </div>
                                <div class=""row mb-1"">
                                    <label class=""form-label"">Điện thoại<span style=""color:red;"">*</span></label>
                                    <div class=""input-group"">
                                        <button class=""btn btn-outline-secondary dropdown-toggle"" type=""button"" data-bs-toggle=""dropdown"" aria-expanded=""false"">Vietn");
                WriteLiteral(@"am (84)</button>
                                        <ul class=""dropdown-menu"">
                                            <li><a class=""dropdown-item"" href=""#"">Vietnam (84)</a></li>
                                        </ul>
                                        <input id=""Tel"" name=""Tel"" onchange=""checkTel()"" type=""number"" class=""form-control"" placeholder=""0xxxxxxxxx"" required>
                                    </div>
                                </div>
                                <div class=""row mb-1"">
                                    <label class=""form-label"">Quốc tịch<span style=""color:red;"">*</span></label>
                                    <div class=""col-sm-4"">
                                        <select name=""Nationality"" class=""form-select"" required>
                                            <option value=""Việt Nam"">Viet Nam</option>
                                        </select>
                                    </div>
                               ");
                WriteLiteral(@" </div>
                                <div class=""row mb-1"">
                                    <label class=""form-label"">Ghi chú</label>
                                    <div class=""col-sm-12"">
                                        <textarea name=""Note"" class=""form-control""");
                EndContext();
                BeginWriteAttribute("id", " id=\"", 9544, "\"", 9549, 0);
                EndWriteAttribute();
                BeginContext(9550, 504, true);
                WriteLiteral(@" rows=""3""></textarea>
                                    </div>
                                </div>
                                <div class=""d-grid"">
                                    <button class=""btn btn-primary"" type=""submit"">Đăng ký</button>
                                </div>
                            </div>
                        </div>
                        <div class=""col-sm-6"">
                            <div class=""contain-img"">
                                ");
                EndContext();
                BeginContext(10055, 23, false);
#line 209 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                           Write(Html.Raw(Content_Right));

#line default
#line hidden
                EndContext();
                BeginContext(10078, 98, true);
                WriteLiteral("\r\n                            </div>\r\n                        </div>\r\n                    </div>\r\n");
                EndContext();
#line 213 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
                }

#line default
#line hidden
                BeginContext(10195, 50, true);
                WriteLiteral("            </div>\r\n        </div>\r\n    </div>\r\n\r\n");
                EndContext();
#line 218 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
     if (ViewBag.message != null)
    {

#line default
#line hidden
                BeginContext(10287, 53, true);
                WriteLiteral("        <script charset=\"UTF-8\">\r\n            alert(\'");
                EndContext();
                BeginContext(10341, 25, false);
#line 221 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
              Write(Html.Raw(ViewBag.message));

#line default
#line hidden
                EndContext();
                BeginContext(10366, 24, true);
                WriteLiteral("\');\r\n        </script>\r\n");
                EndContext();
#line 223 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Lotusmile\SignupLotusmile.cshtml"
    }

#line default
#line hidden
                BeginContext(10397, 1355, true);
                WriteLiteral(@"    <script>
        function checkTel() {
            var tel = document.getElementById(""Tel"").value;
            if (tel.length != 10) {
                alert(""Số điện thoại phải có 10 ký tự"");
            }
        }
        function xoa_dau(id) {
            var str = document.getElementById(id).value;
            str = str.replace(/à|á|ạ|ả|ã|â|ầ|ấ|ậ|ẩ|ẫ|ă|ằ|ắ|ặ|ẳ|ẵ/g, 'a');
            str = str.replace(/è|é|ẹ|ẻ|ẽ|ê|ề|ế|ệ|ể|ễ/g, 'e');
            str = str.replace(/ì|í|ị|ỉ|ĩ/g, 'i');
            str = str.replace(/ò|ó|ọ|ỏ|õ|ô|ồ|ố|ộ|ổ|ỗ|ơ|ờ|ớ|ợ|ở|ỡ/g, 'o');
            str = str.replace(/ù|ú|ụ|ủ|ũ|ư|ừ|ứ|ự|ử|ữ/g, 'u');
            str = str.replace(/ỳ|ý|ỵ|ỷ|ỹ/g, 'y');
            str = str.replace(/đ/g, 'd');
            str = str.replace(/À|Á|Ạ|Ả|Ã|Â|Ầ|Ấ|Ậ|Ẩ|Ẫ|Ă|Ằ|Ắ|Ặ|Ẳ|Ẵ/g, 'A');
            str = str.replace(/È|É|Ẹ|Ẻ|Ẽ|Ê|Ề|Ế|Ệ|Ể|Ễ/g, 'E');
            str = str.replace(/Ì|Í|Ị|Ỉ|Ĩ/g, 'I');
            str = str.replace(/Ò|Ó|Ọ|Ỏ|Õ|Ô|Ồ|Ố|Ộ|Ổ|Ỗ|Ơ|Ờ|Ớ|Ợ|Ở|Ỡ/g, 'O');
            str = str.");
                WriteLiteral(@"replace(/Ù|Ú|Ụ|Ủ|Ũ|Ư|Ừ|Ứ|Ự|Ử|Ữ/g, 'U');
            str = str.replace(/Ỳ|Ý|Ỵ|Ỷ|Ỹ/g, 'Y');
            str = str.replace(/Đ/g, 'D');
            // Gộp nhiều dấu space thành 1 space
            str = str.replace(/\s+/g, ' ');
            document.getElementById(id).value = str.toUpperCase().trim();
        }
    </script>
");
                EndContext();
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_BodyTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.BodyTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_BodyTagHelper);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            EndContext();
            BeginContext(11759, 11, true);
            WriteLiteral("\r\n\r\n</html>");
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
