#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "2100e73317f5f5a0590648f08d39654c150f245c"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Ketoan_CongNoQuaHan), @"mvc.1.0.view", @"/Views/Ketoan/CongNoQuaHan.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Ketoan/CongNoQuaHan.cshtml", typeof(AspNetCore.Views_Ketoan_CongNoQuaHan))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"2100e73317f5f5a0590648f08d39654c150f245c", @"/Views/Ketoan/CongNoQuaHan.cshtml")]
    public class Views_Ketoan_CongNoQuaHan : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<List<BongSenVang.Models.CongNoQuaHanModel>>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/js/KeToan/CongNoQuaHan.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
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
#line 2 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
  
    ViewData["Title"] = "BÁO CÁO CÔNG NỢ QUÁ HẠN";
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(162, 10, true);
            WriteLiteral("\r\n<title> ");
            EndContext();
            BeginContext(173, 17, false);
#line 7 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
   Write(ViewData["Title"]);

#line default
#line hidden
            EndContext();
            BeginContext(190, 1599, true);
            WriteLiteral(@" </title>
<h2>BÁO CÁO CÔNG NỢ QUÁ HẠN</h2>

<div class=""x_panel"">
    <div id=""demo-form3"" class=""form-horizontal form-label-left"">
        <div class=""row"" style=""margin-bottom:10px;"">
            <div class=""col-sm-4 col-xs-6"">
                <div class=""form-group"">
                    <input type=""file"" class=""form-control-file btn btn-info"" style=""width:100%;"" id=""files_new"" name=""files_new"">
                </div>
            </div>
            <div class=""col-sm-2 col-xs-3"">
                <div class=""form-group"" style=""font-size: 14px;padding-top: 10px;"">
                    <a href=""http://gateway.enviet-group.com/Files/FileMauCongNoQuaHan.xlsx"">File Mẫu</a>
                </div>
            </div>
            <div class=""col-sm-2 col-xs-3"">
                <div class=""form-group"">
                    <input class=""btn btn-info"" onclick=""ImportExcel(this);"" type=""button"" value=""Import"">
                </div>
            </div>
        </div>
        <div class=""row"">
      ");
            WriteLiteral(@"      <div class=""col-sm-3 col-xs-12"">
                <div class=""row"">
                    <label class=""col-xs-12"">
                        Tiêu đề
                    </label>
                    <fieldset class=""col-xs-12"" style=""padding:0px"">
                        <div class=""control-group"">
                            <div class=""controls"">
                                <div class="" xdisplay_inputx form-group has-feedback"" style=""padding-left:10px"">
                                    <input class=""form-control"" type=""type"" id=""TieuDe"" name=""TieuDe""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1789, "\"", 1797, 0);
            EndWriteAttribute();
            BeginContext(1798, 6603, true);
            WriteLiteral(@" placeholder=""Tiêu đề"" />
                                    <input class=""form-control"" type=""hidden"" id=""ID"" name=""ID"" />
                                </div>
                            </div>
                        </div>
                    </fieldset>
                </div>
            </div>
            <div class=""col-sm-2 col-xs-12"">
                <div class=""row"">
                    <label class=""col-xs-12"">
                        Tháng
                    </label>
                    <fieldset class=""col-xs-12"" style=""padding:0px"">
                        <div class=""control-group"">
                            <div class=""controls"">
                                <div class="" xdisplay_inputx form-group has-feedback"" style=""padding-left:10px"">
                                    <select id=""Thang"" name=""Thang"" class=""form-control"">
                                        <option value=""1"">1</option>
                                        <option value=""2"">2</option>
   ");
            WriteLiteral(@"                                     <option value=""3"">3</option>
                                        <option value=""4"">4</option>
                                        <option value=""5"">5</option>
                                        <option value=""6"">6</option>
                                        <option value=""7"">7</option>
                                        <option value=""8"">8</option>
                                        <option value=""9"">9</option>
                                        <option value=""10"">10</option>
                                        <option value=""11"">11</option>
                                        <option value=""12"">12</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </fieldset>
                </div>
            </div>
            <div class=""col-sm-1 col-xs-12"">
                <div class=""row"">
        ");
            WriteLiteral(@"            <label class=""col-xs-12"">
                        &nbsp;
                    </label>
                    <fieldset class=""col-xs-12"" style=""padding:0px"">
                        <input class=""btn btn-primary"" onclick=""UpdateCongNoQuaHan(this);"" type=""button"" id=""UpdateData"" style=""float:right"" value=""Update"" />
                    </fieldset>
                </div>
            </div>
        </div>
        <div id=""Rows"">
            <div class=""row"" id=""SoDong"">
                <div class=""col-md-1 col-xs-4"">
                    <div class=""item form-group"">
                        <input type=""text"" placeholder=""MaNV"" id=""MaNV"" asp-for=""MaNV"" name=""MaNV"" class=""form-control "">
                    </div>
                </div>
                <div class=""col-md-2 col-xs-4"">
                    <div class=""item form-group"">
                        <input type=""text"" placeholder=""Tên NV"" id=""TenNV"" asp-for=""TenNV"" name=""TenNV"" class=""form-control "">
                    </div>
 ");
            WriteLiteral(@"               </div>
                <div class=""col-md-2 col-xs-4"">
                    <div class=""item form-group"">
                        <input type=""text"" placeholder=""Số tiền nợ"" id=""SoTienNo"" asp-for=""SoTienNo"" name=""SoTienNo"" onblur=""formatNumberCNQH(this.value, this.id)"" class=""form-control "">
                    </div>
                </div>
                <div class=""col-md-1 col-xs-4"">
                    <div class=""item form-group"">
                        <input type=""text"" placeholder=""Thời gian xuất vé"" id=""ThoiGianXuatVe"" asp-for=""ThoiGianXuatVe"" name=""ThoiGianXuatVe"" class=""form-control "">
                    </div>
                </div>
                <div class=""col-md-2 col-xs-4"">
                    <div class=""item form-group"">
                        <input type=""text"" placeholder=""Dư nợ hiện tại"" id=""DuNo"" asp-for=""DuNo"" name=""DuNo"" onblur=""formatNumberCNQH(this.value, this.id)"" class=""form-control "">
                    </div>
                </div>
           ");
            WriteLiteral(@"     <div class=""col-md-1 col-xs-4"">
                    <div class=""item form-group"">
                        <div class=""control-group"">
                            <div class=""controls"">
                                <div class="" xdisplay_inputx form-group has-feedback"">
                                    <select id=""TinhTrang"" name=""TinhTrang"" class=""form-control"" style="" padding-right: 0px;"">
                                        <option value=""Normal"">Normal</option>
                                        <option value=""High"">High</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class=""col-md-2 col-xs-4"">
                    <div class=""item form-group"">
                        <input type=""text"" placeholder=""Ghi chú"" id=""GhiChu"" asp-for=""GhiChu"" name=""GhiChu"" class=""form-control "">
                   ");
            WriteLiteral(@" </div>
                </div>
                <div class=""col-md-1 col-xs-6"">
                    <div class=""item form-group"">
                        <input class=""btn btn-primary"" onclick=""ThemDong(this);"" type=""button"" value=""+"" />
                    </div>
                </div>
            </div>
            <div id=""addRows"">
            </div>
            <br />
            <div class=""row"">
                <div class=""col-xs-12"">
                    <input class=""btn btn-success"" onclick=""LuuCongNoQuaHan(this);"" type=""button"" id=""SaveData"" style=""float:right"" value=""Lưu báo cáo"" />
                </div>
            </div>
        </div>
    </div>
</div>
<div class=""x_panel"">
    <div id=""demo-form3"" class=""form-horizontal form-label-left"">
        <div class=""row"">
            <div class=""table-responsive"">
                <table id=""gridCNNVQH"" class=""table table-striped jambo_table bulk_action table-bordered"">
                    <thead>
                        <tr clas");
            WriteLiteral(@"s=""headings"" style=""font-size:12px;"">
                            <th class=""column-title"">STT </th>
                            <th class=""column-title"">Tiêu đề</th>
                            <th class=""column-title"">Tháng</th>
                            <th class=""column-title"">UpdateBy</th>
                            <th class=""column-title"">Import</th>
                        </tr>
                    </thead>
                    <tbody>
");
            EndContext();
#line 165 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
                         if (Model != null)
                        {
                            int i = 1;
                            

#line default
#line hidden
#line 168 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
                             foreach (var item in Model)
                            {

#line default
#line hidden
            BeginContext(8602, 80, true);
            WriteLiteral("                                <tr class=\"even pointer\" style=\"font-size:12px;\"");
            EndContext();
            BeginWriteAttribute("id", " id=\"", 8682, "\"", 8695, 1);
#line 170 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
WriteAttributeValue("", 8687, item.ID, 8687, 8, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(8696, 42, true);
            WriteLiteral(">\r\n                                    <td");
            EndContext();
            BeginWriteAttribute("class", " class=\"", 8738, "\"", 8746, 0);
            EndWriteAttribute();
            BeginContext(8747, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(8749, 1, false);
#line 171 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
                                            Write(i);

#line default
#line hidden
            EndContext();
            BeginContext(8750, 46, true);
            WriteLiteral("</td>\r\n                                    <td");
            EndContext();
            BeginWriteAttribute("class", " class=\"", 8796, "\"", 8804, 0);
            EndWriteAttribute();
            BeginContext(8805, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(8807, 11, false);
#line 172 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
                                            Write(item.TieuDe);

#line default
#line hidden
            EndContext();
            BeginContext(8818, 46, true);
            WriteLiteral("</td>\r\n                                    <td");
            EndContext();
            BeginWriteAttribute("class", " class=\"", 8864, "\"", 8872, 0);
            EndWriteAttribute();
            BeginContext(8873, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(8875, 10, false);
#line 173 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
                                            Write(item.Thang);

#line default
#line hidden
            EndContext();
            BeginContext(8885, 46, true);
            WriteLiteral("</td>\r\n                                    <td");
            EndContext();
            BeginWriteAttribute("class", " class=\"", 8931, "\"", 8939, 0);
            EndWriteAttribute();
            BeginContext(8940, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(8942, 13, false);
#line 174 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
                                            Write(item.UpdateBy);

#line default
#line hidden
            EndContext();
            BeginContext(8955, 275, true);
            WriteLiteral(@"</td>
                                    <td><a class=""ImportData"" data-toggle=""modal"" data-target=""#openPopup"" href=""javascript:;""><i style=""font-size:14px;color:red"" class=""fa fa-arrow-circle-down"" aria-hidden=""true""></i></a></td>
                                </tr>
");
            EndContext();
#line 177 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
                                i++;
                            }

#line default
#line hidden
#line 178 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
                             
                        }

#line default
#line hidden
            BeginContext(9326, 177, true);
            WriteLiteral("                    </tbody>\r\n                </table>\r\n            </div>\r\n        </div>\r\n    </div>\r\n</div>\r\n<div class=\"modal fade\" id=\"openPopup\" role=\"dialog\">\r\n</div>\r\n\r\n");
            EndContext();
#line 189 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
 if (ViewBag.msg != "" && ViewBag.msg != null)
{

#line default
#line hidden
            BeginContext(9554, 45, true);
            WriteLiteral("    <script charset=\"UTF-8\">\r\n        alert(\'");
            EndContext();
            BeginContext(9600, 21, false);
#line 192 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
          Write(Html.Raw(ViewBag.msg));

#line default
#line hidden
            EndContext();
            BeginContext(9621, 20, true);
            WriteLiteral("\');\r\n    </script>\r\n");
            EndContext();
#line 194 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Ketoan\CongNoQuaHan.cshtml"
}

#line default
#line hidden
            BeginContext(9644, 224, true);
            WriteLiteral("<script type=\"text/javascript\" src=\"https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.13.5/xlsx.full.min.js\"></script>\r\n<script type=\"text/javascript\" src=\"https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.13.5/jszip.js\"></script>\r\n");
            EndContext();
            BeginContext(9868, 51, false);
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "2100e73317f5f5a0590648f08d39654c150f245c18400", async() => {
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
            BeginContext(9919, 2, true);
            WriteLiteral("\r\n");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<List<BongSenVang.Models.CongNoQuaHanModel>> Html { get; private set; }
    }
}
#pragma warning restore 1591
