#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "a9deeae9f3c3c5264e01d8469fc54413361c63a1"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_KyThuat_Flight), @"mvc.1.0.view", @"/Views/KyThuat/Flight.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/KyThuat/Flight.cshtml", typeof(AspNetCore.Views_KyThuat_Flight))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"a9deeae9f3c3c5264e01d8469fc54413361c63a1", @"/Views/KyThuat/Flight.cshtml")]
    public class Views_KyThuat_Flight : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<List<BongSenVang.Models.FlightModel>>
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
#line 2 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
  
    ViewData["Title"] = "Danh sách hành trình";
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(153, 9, true);
            WriteLiteral("\r\n<title>");
            EndContext();
            BeginContext(163, 17, false);
#line 7 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
  Write(ViewData["Title"]);

#line default
#line hidden
            EndContext();
            BeginContext(180, 62, true);
            WriteLiteral("</title>\r\n<h2 style=\"color: #000;\">Danh sách hành trình</h2>\r\n");
            EndContext();
#line 9 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
 using (Html.BeginForm("Flight", "KyThuat", new { i = 14 }, FormMethod.Get))
{

#line default
#line hidden
            BeginContext(323, 25, true);
            WriteLiteral("    <div class=\"row\">\r\n\r\n");
            EndContext();
#line 13 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
         if (ViewBag.thongbao != null)
        {

#line default
#line hidden
            BeginContext(399, 69, true);
            WriteLiteral("            <script charset=\"UTF-8\">\r\n\r\n                      alert(\'");
            EndContext();
            BeginContext(469, 26, false);
#line 17 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                        Write(Html.Raw(ViewBag.thongbao));

#line default
#line hidden
            EndContext();
            BeginContext(495, 28, true);
            WriteLiteral("\');\r\n            </script>\r\n");
            EndContext();
#line 19 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"

        }

#line default
#line hidden
            BeginContext(536, 997, true);
            WriteLiteral(@"
    </div>
    <div class=""row"">

        <div class=""form-group"">
            <input class=""btn btn-primary"" id=""saveBtn"" type=""button"" name=""saveBtn"" value=""Thêm hành trình"" />
        </div>

    </div>
    <div class=""row"">

        <div id=""gridTable"" class=""gridTable table-responsive"">
            <table class=""table table-bordered table-hover"">
                <thead>
                    <tr>
                        <th></th>
                        <th>STT</th>
                        <th>Hãng</th>
                        <th>Hành Trình</th>
                        <th>Ngày đi</th>
                        <th>Giờ đi</th>                       
                        <th>Số lượng</th>
                        <th>Đơn giá</th>
                        <th>Đơn giá giảm</th>
                        <th>Loại chuyến</th>

                        <th>Ngày tạo</th>

                        <th>Số lượng người(Đoàn)</th>
                        <th></th>
");
            EndContext();
            BeginContext(1578, 78, true);
            WriteLiteral("                    </tr>\r\n                </thead>\r\n                <tbody>\r\n");
            EndContext();
#line 55 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                     if (Model.Count < 1)
                    {

#line default
#line hidden
            BeginContext(1722, 235, true);
            WriteLiteral("                        <tr class=\"even pointer\">\r\n                            <td colspan=\"12\">\r\n                                <i>Không có thông tin để hiển thị</i>\r\n                            </td>\r\n                        </tr>\r\n");
            EndContext();
#line 62 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                    }
                    else
                    {
                        int i = 1;
                        foreach (var item in Model)
                        {


#line default
#line hidden
            BeginContext(2147, 19, true);
            WriteLiteral("                <tr");
            EndContext();
            BeginWriteAttribute("id", " id=\"", 2166, "\"", 2179, 1);
#line 69 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
WriteAttributeValue("", 2171, item.ID, 2171, 8, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(2180, 224, true);
            WriteLiteral(" style=\"cursor:pointer\">\r\n                    <td style=\"text-align:center\"><a class=\"Flight\" style=\"color:red;\" href=\"javascript:;\"><i class=\"fa fa-pencil-square-o\" aria-hidden=\"true\"></i></a></td>\r\n                    <td>");
            EndContext();
            BeginContext(2405, 1, false);
#line 71 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                   Write(i);

#line default
#line hidden
            EndContext();
            BeginContext(2406, 31, true);
            WriteLiteral("</td>\r\n                    <td>");
            EndContext();
            BeginContext(2438, 12, false);
#line 72 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                   Write(item.Airline);

#line default
#line hidden
            EndContext();
            BeginContext(2450, 31, true);
            WriteLiteral("</td>\r\n                    <td>");
            EndContext();
            BeginContext(2482, 14, false);
#line 73 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                   Write(item.Itinerary);

#line default
#line hidden
            EndContext();
            BeginContext(2496, 33, true);
            WriteLiteral("</td>\r\n                    <td>\r\n");
            EndContext();
#line 75 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                         foreach (var detail in item.ListFlightDetail)
                        {

#line default
#line hidden
            BeginContext(2628, 33, true);
            WriteLiteral("                            <div>");
            EndContext();
            BeginContext(2662, 40, false);
#line 77 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                            Write(detail.FlightDate.ToString("dd/MM/yyyy"));

#line default
#line hidden
            EndContext();
            BeginContext(2702, 8, true);
            WriteLiteral("</div>\r\n");
            EndContext();
#line 78 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                        }

#line default
#line hidden
            BeginContext(2737, 53, true);
            WriteLiteral("                    </td>\r\n                    <td>\r\n");
            EndContext();
#line 81 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                         foreach (var detail in item.ListFlightDetail)
                        {

#line default
#line hidden
            BeginContext(2889, 33, true);
            WriteLiteral("                            <div>");
            EndContext();
            BeginContext(2923, 17, false);
#line 83 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                            Write(detail.FlightHour);

#line default
#line hidden
            EndContext();
            BeginContext(2940, 8, true);
            WriteLiteral("</div>\r\n");
            EndContext();
#line 84 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                        }

#line default
#line hidden
            BeginContext(2975, 51, true);
            WriteLiteral("                    </td>\r\n                    <td>");
            EndContext();
            BeginContext(3027, 19, false);
#line 86 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                   Write(item.NumberOfGuests);

#line default
#line hidden
            EndContext();
            BeginContext(3046, 31, true);
            WriteLiteral("</td>\r\n                    <td>");
            EndContext();
            BeginContext(3078, 36, false);
#line 87 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                   Write(string.Format("{0:0,0}", item.Price));

#line default
#line hidden
            EndContext();
            BeginContext(3114, 31, true);
            WriteLiteral("</td>\r\n                    <td>");
            EndContext();
            BeginContext(3146, 41, false);
#line 88 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                   Write(string.Format("{0:0,0}", item.PriceAgent));

#line default
#line hidden
            EndContext();
            BeginContext(3187, 31, true);
            WriteLiteral("</td>\r\n                    <td>");
            EndContext();
            BeginContext(3219, 13, false);
#line 89 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                   Write(item.KindTrip);

#line default
#line hidden
            EndContext();
            BeginContext(3232, 33, true);
            WriteLiteral(" </td>\r\n                     <td>");
            EndContext();
            BeginContext(3266, 16, false);
#line 90 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                    Write(item.CreatedDate);

#line default
#line hidden
            EndContext();
            BeginContext(3282, 32, true);
            WriteLiteral(" </td>\r\n                    <td>");
            EndContext();
            BeginContext(3315, 18, false);
#line 91 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                   Write(item.Specification);

#line default
#line hidden
            EndContext();
            BeginContext(3333, 224, true);
            WriteLiteral(" </td>\r\n                    <td style=\"text-align:center;\"><a class=\"DeleteFlight\" style=\"color: red; font-size: 14px;\" href=\"javascript:;\"><i class=\"fa fa-trash-o\" aria-hidden=\"true\"></i></a></td>\r\n\r\n                </tr>\r\n");
            EndContext();
#line 95 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
                            i++;
                        }
                    }

#line default
#line hidden
            BeginContext(3641, 80, true);
            WriteLiteral("\r\n\r\n                </tbody>\r\n            </table>\r\n        </div>\r\n    </div>\r\n");
            EndContext();
#line 104 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\Flight.cshtml"
}

#line default
#line hidden
            BeginContext(3724, 133, true);
            WriteLiteral("\r\n<div class=\"modal fade\" id=\"openPopup1\" role=\"dialog\">\r\n</div>\r\n\r\n<div class=\"modal fade\" id=\"openPopup\" role=\"dialog\">\r\n</div>\r\n\r\n");
            EndContext();
            BeginContext(3857, 48, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "a9deeae9f3c3c5264e01d8469fc54413361c63a115256", async() => {
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
            BeginContext(3905, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(3907, 47, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "a9deeae9f3c3c5264e01d8469fc54413361c63a116436", async() => {
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
            BeginContext(3954, 2, true);
            WriteLiteral("\r\n");
            EndContext();
            BeginContext(3956, 57, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("link", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.SelfClosing, "a9deeae9f3c3c5264e01d8469fc54413361c63a117616", async() => {
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
            BeginContext(4013, 2583, true);
            WriteLiteral(@"

<script>


 
    $(""#saveBtn"").click(function () {

        $.ajax({
            type: ""GET"",
            url: ""/KyThuat/CreateFlight"",
            success: function (response) {
                $('#openPopup1').html(response);
             
                $('#openPopup1').modal({
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

    $(""#gridTable .DeleteFlight"").click(function () {

        /*var index = $('#gridVeHoan tr').index($(this).closest('tr'));*/
        var id = String($(this).closest('tr').attr('id'));
        let text = ""Bạn có chắc muốn xóa hành trình này."";
        if (confirm(text) == true) {
            $.ajax({
                type: ");
            WriteLiteral(@"""POST"",
                url: ""/KyThuat/DeleteFlightData"",
                data: { khoachinh: id },
                success: function (response) {
                    if (response == ""false"") {
                        alert(""Xóa thất bại"");
                    }
                    else {
                        alert(""Xóa thành công"");
                        location.reload();
                    }

                },
                failure: function (response) {
                    alert(response.responseText);
                },
                error: function (response) {
                    alert(response.responseText);
                }
            });
        }
        
    });

    $(""#gridTable .Flight"").click(function () {

        /*var index = $('#gridVeHoan tr').index($(this).closest('tr'));*/
        var id = String($(this).closest('tr').attr('id'));

        $.ajax({
            type: ""POST"",
            url: ""/KyThuat/UpdateFlight"",
            data: { khoachin");
            WriteLiteral(@"h: id },
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<List<BongSenVang.Models.FlightModel>> Html { get; private set; }
    }
}
#pragma warning restore 1591