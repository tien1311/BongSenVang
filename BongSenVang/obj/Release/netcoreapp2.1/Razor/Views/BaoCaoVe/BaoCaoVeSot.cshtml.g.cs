#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\BaoCaoVeSot.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "d33e61ae65019be183525d57fee2f4981422fa58"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_BaoCaoVe_BaoCaoVeSot), @"mvc.1.0.view", @"/Views/BaoCaoVe/BaoCaoVeSot.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/BaoCaoVe/BaoCaoVeSot.cshtml", typeof(AspNetCore.Views_BaoCaoVe_BaoCaoVeSot))]
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
#line 1 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\BaoCaoVeSot.cshtml"
using System.Globalization;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"d33e61ae65019be183525d57fee2f4981422fa58", @"/Views/BaoCaoVe/BaoCaoVeSot.cshtml")]
    public class Views_BaoCaoVe_BaoCaoVeSot : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.TongQuatMail>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/js/PhongVe/GuiMailDaiLy.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
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
#line 3 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\BaoCaoVeSot.cshtml"
  
    ViewData["Title"] = "Nhập báo cáo vé";
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(173, 10, true);
            WriteLiteral("\r\n<title> ");
            EndContext();
            BeginContext(184, 17, false);
#line 8 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\BaoCaoVeSot.cshtml"
   Write(ViewData["Title"]);

#line default
#line hidden
            EndContext();
            BeginContext(201, 1998, true);
            WriteLiteral(@" </title>
<h2>Nhập báo cáo vé</h2>

<div class=""row"">
    <div class=""col-md-12 col-sm-12 col-xs-12"">
        <div class=""x_panel"">
            <div id=""demo-form3"" class=""form-horizontal form-label-left"">
                <div class=""row"">
                    <div class=""col-sm-4 col-xs-6"">
                        <div class=""form-group"">
                            <input type=""file"" class=""form-control-file btn btn-primary"" style=""width:100%;"" id=""files_new"" name=""files_new"">

                        </div>
                    </div>
                    <div class=""col-sm-2 col-xs-3"">
                        <div class=""form-group"" style=""font-size: 14px;padding-top: 10px;"">
                            <a href=""http://gateway.enviet-group.com/Files/FileMauXuatDoiVe.xlsx"">File Mẫu</a>
                        </div>
                    </div>
                    <div class=""col-sm-2 col-xs-3"">
                        <div class=""form-group"">
                            <input class=""btn b");
            WriteLiteral(@"tn-primary"" onclick=""ImportExcel(this);"" type=""button"" value=""Import"">
                        </div>
                    </div>
                </div>
                <div class=""row"">
                    <div class=""x_panel"">
                        <div class=""x_title"">
                            <span style=""color:red;font-size:14px"">
                                Lưu ý khi nhập báo cáo vé:
                            </span>
                            <ul class=""nav navbar-right panel_toolbox"">
                                <li style=""float:right;"">
                                    <a class=""collapse-link"" style=""padding:0px !important;color:red;""><i class=""fa fa-angle-double-down fa-2x""></i></a>
                                </li>
                            </ul>
                            <div class=""clearfix""></div>
                        </div>
                        <div class=""x_content"">
                            ");
            EndContext();
            BeginContext(2200, 26, false);
#line 47 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\BaoCaoVeSot.cshtml"
                       Write(Html.Raw(@ViewBag.NoiDung));

#line default
#line hidden
            EndContext();
            BeginContext(2226, 6684, true);
            WriteLiteral(@"
                        </div>
                    </div>
                </div>
                <div class=""row"">
                    <div style="" margin-top: 10px; margin-left: 10px;"">
                        <div class=""item form-group"">
                            <span style=""color:red;font-size:14px"">
                                Số tiền mặc định: VNĐ
                            </span>
                        </div>
                    </div>
                </div>
                <div id=""Rows"">
                    <div class=""row"" id=""RowTenKH"">
                        <div style=""margin-top: 10px;margin-left: 10px;"">
                            <div class=""item form-group"" style=""margin-bottom: 0px;"">
                                <span style=""font-size: 12px;color: #3300ff"">
                                    <label id=""TENKH_NEW""></label>
                                </span>
                            </div>
                        </div>

                    </di");
            WriteLiteral(@"v>
                    <div class=""row"" id=""SoDong"">
                        <div class=""col-md-1 col-xs-4"">
                            <div class=""item form-group"">
                                <input type=""text"" placeholder=""Hãng"" id=""MAHHK"" asp-for=""MAHHK"" name=""MAHHK"" class=""form-control "">
                            </div>
                        </div>
                        <div class=""col-md-2 col-xs-8"">
                            <div class=""item form-group"">
                                <div class=""input-group"" style=""margin:0px"">
                                    <input type=""text"" placeholder=""Mã KH"" id=""MAKH_NEW"" asp-for=""MAKH_NEW"" name=""MAKH_NEW"" class=""form-control "">
                                    <span class=""input-group-btn"">
                                        <button id=""check"" onclick=""CheckMaKH('MAKH_NEW','TENKH_NEW');"" class=""btn btn-info"" type=""button"" style=""margin-bottom:0px; ""><i class=""fa fa-search"" aria-hidden=""true""></i></button>
                ");
            WriteLiteral(@"                    </span>
                                </div>
                            </div>
                        </div>
                        <div class=""col-md-1 col-xs-4"">
                            <div class=""item form-group"">
                                <input type=""text"" placeholder=""PNR"" id=""PNR_NEW"" asp-for=""PNR_NEW"" name=""PNR_NEW"" class=""form-control "">
                            </div>
                        </div>
                        <div class=""col-md-2 col-xs-4"">
                            <div class=""item form-group"">
                                <input type=""text"" placeholder=""Số vé"" id=""SoVe"" asp-for=""SoVe"" name=""SoVe"" class=""form-control "">
                            </div>
                        </div>
                        <div class=""col-md-2 col-xs-4"">
                            <div class=""item form-group"">
                                <input type=""text"" placeholder=""Giá mua"" onkeyup=""formatNumber(document.getElementById(this.id).valu");
            WriteLiteral(@"e,this.id);"" id=""GiaMua"" asp-for=""GiaMua"" name=""GiaMua"" class=""form-control "">
                            </div>
                        </div>
                        <div class=""col-md-2 col-xs-4"" hidden>
                            <div class=""item form-group"">
                                <input type=""text"" placeholder=""Phí DV mua"" onkeyup=""formatNumber(document.getElementById(this.id).value,this.id);"" id=""PhiDVMua"" asp-for=""PhiDVMua"" name=""PhiDVMua"" class=""form-control "">
                            </div>
                        </div>
                        <div class=""col-md-2 col-xs-4"">
                            <div class=""item form-group"">
                                <input type=""text"" placeholder=""Phí DV bán"" onkeyup=""formatNumber(document.getElementById(this.id).value,this.id);"" id=""PhiDVBan"" asp-for=""PhiDVBan"" name=""PhiDVBan"" class=""form-control "">
                            </div>
                        </div>
                        <div class=""col-md-2 col-xs-4"">
  ");
            WriteLiteral(@"                          <div class=""item form-group"">
                                <input type=""text"" placeholder=""Phí hoàn"" onkeyup=""formatNumber(document.getElementById(this.id).value,this.id);"" id=""PhiHoan"" asp-for=""PhiHoan"" name=""PhiHoan"" class=""form-control "">
                            </div>
                        </div>
                        <div class=""col-md-2 col-xs-4"">
                            <div class=""item form-group"">
                                <input type=""text"" placeholder=""Chiết khấu"" onkeyup=""formatNumber(document.getElementById(this.id).value,this.id);"" id=""ChietKhau"" asp-for=""ChietKhau"" name=""ChietKhau"" class=""form-control "">
                            </div>
                        </div>
                        <div class=""col-md-2 col-xs-4"">
                            <div class=""item form-group"">
                                <input type=""text"" placeholder=""Ghi chú"" id=""GhiChu"" asp-for=""GhiChu"" name=""GhiChu"" class=""form-control "">
                   ");
            WriteLiteral(@"         </div>
                        </div>
                        <div class=""col-md-2 col-xs-4"">
                            <div class=""item form-group"">
                                <input type=""text"" placeholder=""Mã giới thiệu"" id=""MaGioiThieu"" asp-for=""MaGioiThieu"" name=""MaGioiThieu"" class=""form-control "">
                            </div>
                        </div>
                        <div class=""col-md-2 col-xs-4"">
                            <div class=""item form-group"">
                                <input type=""text"" placeholder=""Người giới thiệu"" id=""NguoiGioiThieu"" asp-for=""NguoiGioiThieu"" name=""NguoiGioiThieu"" class=""form-control "">
                            </div>
                        </div>
                        <div class=""col-md-1 col-xs-6"">
                            <div class=""item form-group"">
                                <input class=""btn btn-primary"" onclick=""ThemDong(this);"" type=""button"" value=""+"" />
                            </div>
    ");
            WriteLiteral(@"                    </div>
                    </div>
                    <div id=""addRows"">
                    </div>
                    <br />
                    <div class=""row"">
                        <div class=""col-xs-12"">
                            <input class=""btn btn-success"" onclick=""LuuBaoCao(this);"" type=""button"" id=""SaveData"" style=""float:right"" value=""Lưu báo cáo"" />
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

");
            EndContext();
            BeginContext(8910, 52, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "d33e61ae65019be183525d57fee2f4981422fa5813573", async() => {
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
            BeginContext(8962, 228, true);
            WriteLiteral("\r\n<script type=\"text/javascript\" src=\"https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.13.5/xlsx.full.min.js\"></script>\r\n<script type=\"text/javascript\" src=\"https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.13.5/jszip.js\"></script>\r\n\r\n");
            EndContext();
#line 161 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\BaoCaoVeSot.cshtml"
 if (ViewBag.msg != "" && ViewBag.msg != null)
{

#line default
#line hidden
            BeginContext(9241, 45, true);
            WriteLiteral("    <script charset=\"UTF-8\">\r\n        alert(\'");
            EndContext();
            BeginContext(9287, 21, false);
#line 164 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\BaoCaoVeSot.cshtml"
          Write(Html.Raw(ViewBag.msg));

#line default
#line hidden
            EndContext();
            BeginContext(9308, 20, true);
            WriteLiteral("\');\r\n    </script>\r\n");
            EndContext();
#line 166 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\BaoCaoVeSot.cshtml"
}

#line default
#line hidden
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Models.TongQuatMail> Html { get; private set; }
    }
}
#pragma warning restore 1591
