#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "a15c3082f675cd94b40c12b167c53a53fc1a2384"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_KyThuat_ListAirportCode), @"mvc.1.0.view", @"/Views/KyThuat/ListAirportCode.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/KyThuat/ListAirportCode.cshtml", typeof(AspNetCore.Views_KyThuat_ListAirportCode))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"a15c3082f675cd94b40c12b167c53a53fc1a2384", @"/Views/KyThuat/ListAirportCode.cshtml")]
    public class Views_KyThuat_ListAirportCode : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<List<BongSenVang.Services.Model.Request.AirportCodeRequest>>
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
#line 2 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
  
    ViewData["Title"] = "Danh sách sân bay";
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(173, 7, true);
            WriteLiteral("<title>");
            EndContext();
            BeginContext(181, 17, false);
#line 6 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
  Write(ViewData["Title"]);

#line default
#line hidden
            EndContext();
            BeginContext(198, 129, true);
            WriteLiteral("</title>\r\n<h2>Danh sách sân bay</h2>\r\n\r\n<div class=\"x_panel\">\r\n    <div class=\"x_content\">\r\n        \r\n        <div class=\"row\">\r\n");
            EndContext();
#line 13 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
             using (Html.BeginForm("ListAirportCode", "KyThuat", new { i = 12 }, FormMethod.Post))
            {

#line default
#line hidden
            BeginContext(442, 949, true);
            WriteLiteral(@"                <div class=""col-sm-1 col-xs-12"" style=""text-align:right;"">
                    <label class=""col-xs-12"">
                        &nbsp;
                    </label>
                    <a id=""BtnCreate"" href=""javascript:;"" type=""button"" class=""btn btn-primary"" style=""margin-bottom:10px"">Tạo mới</a>
                </div>
                <div class=""col-sm-3 col-xs-12"">
                    <div class=""row"">
                        <label class=""col-xs-12"">
                            Code
                        </label>
                        <fieldset class=""col-xs-12"" style=""padding:0px"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"" style=""padding-left:10px"">
                                        <input class=""form-control"" type=""type"" name=""code""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1391, "\"", 1399, 0);
            EndWriteAttribute();
            BeginContext(1400, 560, true);
            WriteLiteral(@" placeholder=""Nhập code sân bay"" />
                                    </div>
                                </div>
                            </div>
                        </fieldset>
                    </div>
                </div>
                <div class=""col-sm-1 col-xs-12"" style=""text-align:right;"">
                    <label class=""col-xs-12"">
                        &nbsp;
                    </label>
                    <button class=""btn btn-success"" name=""btn-Search"" type=""submit"">Tìm kiếm</button>

                </div>
");
            EndContext();
#line 44 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
            }

#line default
#line hidden
            BeginContext(1975, 1129, true);
            WriteLiteral(@"        </div>
    </div>
</div>
<div class=""x_panel"">
    <div class=""x_content"">
        <div class=""table-responsive"" style=""font-size:12px;"">
            <table id=""gridDanhsachDDBL"" class=""table table-striped jambo_table bulk_action"">
                <thead>
                    <tr class=""headings"">
                        <th></th>
                        <th>STT</th>
                        <th>AirportCode</th>
                        <th>AirportName</th>
                        <th>Latitude</th>
                        <th>Longitude</th>
                        <th>TimeZoneOffset</th>
                        <th>IataCode</th>
                        <th>CityName</th>
                        <th>CityCode</th>
                        <th>CountryName</th>
                        <th>CountryCode</th>
                        <th>RegionCode</th>
                        <th>Description</th>
                        <th>CreateDate</th>
                        <th>CreateBy</th>
        ");
            WriteLiteral("                <th></th>\r\n                    </tr>\r\n                </thead>\r\n                <tbody>\r\n");
            EndContext();
#line 74 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                     if (Model != null)
                    {
                        int i = 1;
                        foreach (var item in Model)
                        {

#line default
#line hidden
            BeginContext(3284, 31, true);
            WriteLiteral("                            <tr");
            EndContext();
            BeginWriteAttribute("id", " id=\"", 3315, "\"", 3328, 1);
#line 79 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
WriteAttributeValue("", 3320, item.ID, 3320, 8, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(3329, 223, true);
            WriteLiteral(">\r\n                                <td style=\"text-align:center\"><a class=\"Edit\" style=\"color:red;\" href=\"javascript:;\"><i class=\"fa fa-pencil-square-o\" aria-hidden=\"true\"></i></a></td>\r\n                                <td>");
            EndContext();
            BeginContext(3553, 1, false);
#line 81 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(i);

#line default
#line hidden
            EndContext();
            BeginContext(3554, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(3598, 16, false);
#line 82 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.AirportCode);

#line default
#line hidden
            EndContext();
            BeginContext(3614, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(3658, 16, false);
#line 83 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.AirportName);

#line default
#line hidden
            EndContext();
            BeginContext(3674, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(3718, 13, false);
#line 84 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.Latitude);

#line default
#line hidden
            EndContext();
            BeginContext(3731, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(3775, 14, false);
#line 85 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.Longitude);

#line default
#line hidden
            EndContext();
            BeginContext(3789, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(3833, 19, false);
#line 86 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.TimeZoneOffset);

#line default
#line hidden
            EndContext();
            BeginContext(3852, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(3896, 13, false);
#line 87 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.IataCode);

#line default
#line hidden
            EndContext();
            BeginContext(3909, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(3953, 13, false);
#line 88 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.CityName);

#line default
#line hidden
            EndContext();
            BeginContext(3966, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(4010, 13, false);
#line 89 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.CityCode);

#line default
#line hidden
            EndContext();
            BeginContext(4023, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(4067, 16, false);
#line 90 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.CountryName);

#line default
#line hidden
            EndContext();
            BeginContext(4083, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(4127, 16, false);
#line 91 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.CountryCode);

#line default
#line hidden
            EndContext();
            BeginContext(4143, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(4187, 15, false);
#line 92 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.RegionCode);

#line default
#line hidden
            EndContext();
            BeginContext(4202, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(4246, 16, false);
#line 93 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.Description);

#line default
#line hidden
            EndContext();
            BeginContext(4262, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(4306, 15, false);
#line 94 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.CreateDate);

#line default
#line hidden
            EndContext();
            BeginContext(4321, 43, true);
            WriteLiteral("</td>\r\n                                <td>");
            EndContext();
            BeginContext(4365, 13, false);
#line 95 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                               Write(item.CreateBy);

#line default
#line hidden
            EndContext();
            BeginContext(4378, 218, true);
            WriteLiteral("</td>\r\n                                <td style=\"text-align:center\"><a class=\"Delete\" style=\"color:red;\" href=\"javascript:;\"><i class=\"fa fa-trash\" aria-hidden=\"true\"></i></a></td>\r\n                            </tr>\r\n");
            EndContext();
#line 98 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\ListAirportCode.cshtml"
                            i++;
                        }
                    }

#line default
#line hidden
            BeginContext(4680, 147, true);
            WriteLiteral("                </tbody>\r\n            </table>\r\n        </div>\r\n    </div>\r\n</div>\r\n<div class=\"modal fade\" id=\"openPopup\" role=\"dialog\">\r\n</div>\r\n");
            EndContext();
            BeginContext(4827, 48, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "a15c3082f675cd94b40c12b167c53a53fc1a238416275", async() => {
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
            BeginContext(4875, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(4877, 47, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "a15c3082f675cd94b40c12b167c53a53fc1a238417455", async() => {
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
            BeginContext(4924, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(4926, 57, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("link", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.SelfClosing, "a15c3082f675cd94b40c12b167c53a53fc1a238418635", async() => {
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
            BeginContext(4983, 2997, true);
            WriteLiteral(@"


<script>
    $(""#BtnCreate"").click(function () {
        $.ajax({
            type: ""POST"",
            url: ""/KyThuat/CreateAirportCode"",
            success: function (response) {
                $('#openPopup').html(response);
                $('#openPopup').modal({
                    backdrop: 'static',
                    keyboard: false,
                    show: true
                });
            },
            failure: function (response) {
                alert(response.responseText);
            },
            error: function (response) {
                alert(response.responseText);
            }
        });
    });
    $(""#gridDanhsachDDBL .Edit"").click(function () {
        var id = String($(this).closest('tr').attr('id'));
        var cells = $(this).closest('tr').find('td');

        var Airpost = {};
        Airpost.ID = id;
        Airpost.AirportCode = cells[2].textContent;
        Airpost.AirportName = cells[3].textContent;
        Airpost.Latitude = ce");
            WriteLiteral(@"lls[4].textContent;
        Airpost.Longitude = cells[5].textContent;
        Airpost.TimeZoneOffset = cells[6].textContent;
        Airpost.IataCode = cells[7].textContent;
        Airpost.CityName = cells[8].textContent;
        Airpost.CityCode = cells[9].textContent;
        Airpost.CountryName = cells[10].textContent;
        Airpost.CountryCode = cells[11].textContent;
        Airpost.RegionCode = cells[12].textContent;
        Airpost.Description = cells[13].textContent;
       
        $.ajax({
            type: ""POST"",
            url: ""/KyThuat/EditAirportCode"",
            data: {
                model: Airpost
            },
            success: function (response) {
                $('#openPopup').html(response);
                $('#openPopup').modal({
                    backdrop: 'static',
                    keyboard: false,
                    show: true
                });
            },
            failure: function (response) {
                alert(response.respo");
            WriteLiteral(@"nseText);
            },
            error: function (response) {
                alert(response.responseText);
            }
        });
    });
    $(""#gridDanhsachDDBL .Delete"").click(function () {
        var id = String($(this).closest('tr').attr('id'));
        $.ajax({
            type: ""POST"",
            url: ""/KyThuat/DeleteAirportCode"",
            data: {
                ID: id
            },
            success: function (response) {
                if (response.message == ""Success"") {
                    alert(""Xóa thành công"");
                    window.location.href = 'http://localhost:2075/KyThuat/ListAirportCode?&i=12';

                }
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

");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<List<BongSenVang.Services.Model.Request.AirportCodeRequest>> Html { get; private set; }
    }
}
#pragma warning restore 1591
