#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "c056bb640ce2958c863064103bdcac75b4b79eee"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_BaoCaoVe_DSVeSot), @"mvc.1.0.view", @"/Views/BaoCaoVe/DSVeSot.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/BaoCaoVe/DSVeSot.cshtml", typeof(AspNetCore.Views_BaoCaoVe_DSVeSot))]
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
#line 1 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
using System.Globalization;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"c056bb640ce2958c863064103bdcac75b4b79eee", @"/Views/BaoCaoVe/DSVeSot.cshtml")]
    public class Views_BaoCaoVe_DSVeSot : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.TongQuatMail>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
#line 3 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
  
    ViewData["Title"] = "Danh sách báo cáo vé";
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(178, 8, true);
            WriteLiteral("<title> ");
            EndContext();
            BeginContext(187, 17, false);
#line 7 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
   Write(ViewData["Title"]);

#line default
#line hidden
            EndContext();
            BeginContext(204, 1065, true);
            WriteLiteral(@" </title>

<form asp-controller=""BaoCaoVe"" asp-action=""DSVeSot"" method=""post"" enctype=""multipart/form-data"">
    <div class=""x_panel"">
        <div class=""x_content"">
            <div class=""row"">
                <div class=""form-horizontal"">
                    <div class=""item col-sm-4 col-md-3"">
                        <div class=""form-group"">
                            <label class=""col-form-label pad-top-6 col-sm-3 label-align col-md-4"" for=""first-name"">
                                Từ Ngày
                            </label>
                            <div class=""col-sm-9 col-md-8"">
                                <fieldset class=""col-xs-12"" style=""padding:0px"">
                                    <div class=""control-group"">
                                        <div class=""controls"">
                                            <div class="" xdisplay_inputx form-group has-feedback"">
                                                <input type=""text"" class=""form-control has-feedbac");
            WriteLiteral("k-right\" id=\"single_cal5\" name=\"cal_from\"");
            EndContext();
            BeginWriteAttribute("value", " value=\'", 1269, "\'", 1294, 1);
#line 24 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
WriteAttributeValue("", 1277, ViewBag.DateFrom, 1277, 17, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1295, 536, true);
            WriteLiteral(@">
                                                <span class=""fa fa-calendar-o form-control-feedback right"" aria-hidden=""true""></span>
                                                <span id=""inputSuccess2Status"" class=""sr-only"">(success)</span>
                                            </div>
                                        </div>
                                    </div>
                                </fieldset>
                            </div>
                        </div>
                    </div>
");
            EndContext();
            BeginContext(1941, 674, true);
            WriteLiteral(@"                    <div class=""item col-sm-4 col-md-3"">
                        <div class=""form-group"">
                            <label class=""col-form-label pad-top-6 col-sm-3 label-align col-md-4"" for=""first-name"">
                                Đến Ngày
                            </label>
                            <div class=""col-sm-9 col-md-8"">
                                <fieldset class=""col-xs-12"" style=""padding:0px"">
                                    <div class=""control-group"">
                                        <div class=""controls"">
                                            <div class="" xdisplay_inputx form-group has-feedback""");
            EndContext();
            BeginWriteAttribute("id", " id=\"", 2615, "\"", 2620, 0);
            EndWriteAttribute();
            BeginContext(2621, 140, true);
            WriteLiteral(">\r\n                                                <input type=\"text\" class=\"form-control has-feedback-right\" id=\"single_cal6\" name=\"cal_to\"");
            EndContext();
            BeginWriteAttribute("value", " value=\'", 2761, "\'", 2784, 1);
#line 45 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
WriteAttributeValue("", 2769, ViewBag.DateTo, 2769, 15, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(2785, 1019, true);
            WriteLiteral(@">
                                                <span class=""fa fa-calendar-o form-control-feedback right"" aria-hidden=""true""></span>
                                                <span id=""inputSuccess2Status"" class=""sr-only"">(success)</span>
                                            </div>
                                        </div>
                                    </div>
                                </fieldset>
                            </div>
                        </div>
                    </div>
                    <div class=""col-sm-4 col-md-3"">
                        <div class=""form-group"">
                            <label class=""col-form-label pad-top-6 col-sm-3 label-align col-md-4"" for=""first-name"">
                                Số vé
                            </label>
                            <div class=""col-sm-9 col-md-8"">
                                <input class=""form-control"" type=""text"" id=""SoVeSearch"" name=""SoVeSearch"" placeholder=""Số vé""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 3804, "\"", 3825, 1);
#line 61 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
WriteAttributeValue("", 3812, ViewBag.SoVe, 3812, 13, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(3826, 665, true);
            WriteLiteral(@" />
                            </div>
                        </div>
                    </div>
                    <div class=""col-md-3 col-sm-6 col-xs-12"">
                        <div class=""form-group"">
                            <label class=""col-form-label pad-top-6 col-sm-3 label-align col-md-4"">
                                Tình Trạng
                            </label>
                            <div class=""col-sm-9 col-md-8"" style=""/* padding-right:0px; */"">
                                <select class=""required form-control"" id=""Status"" name=""Status"" style=""/* padding:0 0 0 10px; */"">
                                    <option");
            EndContext();
            BeginWriteAttribute("selected", " selected=\"", 4491, "\"", 4502, 0);
            EndWriteAttribute();
            BeginContext(4503, 348, true);
            WriteLiteral(@" value=""-100"">ALL</option>
                                    <option value=""0"">Báo cáo thường</option>
                                    <option value=""1"">Báo cáo vô quỹ</option>

                                </select>
                            </div>
                        </div>
                    </div>
                   
");
            EndContext();
            BeginContext(5237, 1674, true);
            WriteLiteral(@"
                </div>
            </div>
            <div class=""row"">
                <div class=""col-sm-2 col-md-1"" style=""float:right;"">
                    <button type=""submit"" class=""btn btn-primary"" name=""buttonclick"" value=""search_ve"">Tìm kiếm</button>
                </div>
            </div>
        </div>
    </div>
    <div class=""x_panel"">
        <div class=""x_content"">
            <div class=""row"">
                <div class=""table-responsive"">
                    <table id=""gridVeSot"" class=""table table-bordered table-hover"">
                        <thead>
                            <tr>
                                <th></th>
                                <th>STT</th>
                                <th>Mã Hãng</th>
                                <th>Mã KH</th>
                                <th>Mã KH EFF</th>
                                <th>Code</th>
                                <th>Nhân Viên</th>
                                <th>Ngày</th>
       ");
            WriteLiteral(@"                         <th>PNR</th>
                                <th>Số Vé</th>
                                <th>Giá Mua</th>
                                <th>Phí DV Mua</th>
                                <th>Phí DV Bán</th>
                                <th>Phí hoàn</th>
                                <th>Chiết khấu</th>
                                <th>Ghi chú</th>
                                <th>Mã GT</th>
                                <th>Người GT</th>

                                <th>Đã xong</th>
                            </tr>
                        </thead>
                        <tbody>
");
            EndContext();
#line 128 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                             if (Model != null)
                            {
                                if (Model.ListChiTietVe != null)
                                {
                                    int i = 1;
                                    foreach (var item in Model.ListChiTietVe)
                                    {
                                        if (item.MAKH_EFF != "")
                                        {

#line default
#line hidden
            BeginContext(7367, 47, true);
            WriteLiteral("                                            <tr");
            EndContext();
            BeginWriteAttribute("id", " id=\"", 7414, "\"", 7427, 1);
#line 137 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
WriteAttributeValue("", 7419, item.ID, 7419, 8, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(7428, 3, true);
            WriteLiteral(">\r\n");
            EndContext();
#line 138 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                                  
                                                    DateTime ngaySua = DateTime.ParseExact(item.NGAYSUA, "dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None);
                                                    TimeSpan t = DateTime.Now - ngaySua;
                                                    if (item.CODE == "")
                                                    {
                                                            if (t.TotalMinutes <= Model.TimeOutEdit)
                                                            {

#line default
#line hidden
            BeginContext(8048, 212, true);
            WriteLiteral("                                                                <td><a class=\"VeSot\" style=\"color:blue;\" data-toggle=\"modal\" href=\"javascript:;\"><i class=\"fa fa-pencil-square-o\" aria-hidden=\"true\"></i></a></td>\r\n");
            EndContext();
#line 146 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                                            }
                                                            else
                                                            {

#line default
#line hidden
            BeginContext(8452, 137, true);
            WriteLiteral("                                                                <td><i class=\"fa fa-ban\" style=\"color:red\" aria-hidden=\"true\"></i></td>\r\n");
            EndContext();
#line 150 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                                            }
                                                    }
                                                    else
                                                    {

#line default
#line hidden
            BeginContext(8820, 129, true);
            WriteLiteral("                                                        <td><i class=\"fa fa-ban\" style=\"color:red\" aria-hidden=\"true\"></i></td>\r\n");
            EndContext();
#line 155 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                                    }
                                                

#line default
#line hidden
            BeginContext(9055, 54, true);
            WriteLiteral("\r\n                                                <td>");
            EndContext();
            BeginContext(9110, 1, false);
#line 158 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(i);

#line default
#line hidden
            EndContext();
            BeginContext(9111, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9171, 10, false);
#line 159 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.MAHHK);

#line default
#line hidden
            EndContext();
            BeginContext(9181, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9241, 9, false);
#line 160 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.MAKH);

#line default
#line hidden
            EndContext();
            BeginContext(9250, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9310, 13, false);
#line 161 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.MAKH_EFF);

#line default
#line hidden
            EndContext();
            BeginContext(9323, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9383, 9, false);
#line 162 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.CODE);

#line default
#line hidden
            EndContext();
            BeginContext(9392, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9452, 16, false);
#line 163 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.TenNhanVien);

#line default
#line hidden
            EndContext();
            BeginContext(9468, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9528, 12, false);
#line 164 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.NGAYSUA);

#line default
#line hidden
            EndContext();
            BeginContext(9540, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9600, 8, false);
#line 165 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.PNR);

#line default
#line hidden
            EndContext();
            BeginContext(9608, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9668, 9, false);
#line 166 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.SoVe);

#line default
#line hidden
            EndContext();
            BeginContext(9677, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9737, 11, false);
#line 167 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.GiaMua);

#line default
#line hidden
            EndContext();
            BeginContext(9748, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9808, 13, false);
#line 168 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.PhiDVMua);

#line default
#line hidden
            EndContext();
            BeginContext(9821, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9881, 13, false);
#line 169 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.PhiDVBan);

#line default
#line hidden
            EndContext();
            BeginContext(9894, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(9954, 12, false);
#line 170 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.PhiHoan);

#line default
#line hidden
            EndContext();
            BeginContext(9966, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(10026, 14, false);
#line 171 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.ChietKhau);

#line default
#line hidden
            EndContext();
            BeginContext(10040, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(10100, 11, false);
#line 172 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.GHICHU);

#line default
#line hidden
            EndContext();
            BeginContext(10111, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(10171, 16, false);
#line 173 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.MAGIOITHIEU);

#line default
#line hidden
            EndContext();
            BeginContext(10187, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(10247, 19, false);
#line 174 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.NGUOIGIOITHIEU);

#line default
#line hidden
            EndContext();
            BeginContext(10266, 187, true);
            WriteLiteral("</td>\r\n                                                <td><input id=\"TinhTrangEFF\" type=\"checkbox\" checked=\"checked\" disabled /></td>\r\n                                            </tr>\r\n");
            EndContext();
#line 177 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                        }
                                        else
                                        {

#line default
#line hidden
            BeginContext(10585, 47, true);
            WriteLiteral("                                            <tr");
            EndContext();
            BeginWriteAttribute("id", " id=\"", 10632, "\"", 10645, 1);
#line 180 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
WriteAttributeValue("", 10637, item.ID, 10637, 8, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(10646, 45, true);
            WriteLiteral(" style=\"background-color:red;color:white;\">\r\n");
            EndContext();
#line 181 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                                  

                                                    DateTime ngaySua = DateTime.ParseExact(item.NGAYSUA, "dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None);
                                                    TimeSpan t = DateTime.Now - ngaySua;
                                                    if(item.CODE == "")
                                                    {
                                                            if (t.TotalMinutes <= Model.TimeOutEdit)
                                                            {

#line default
#line hidden
            BeginContext(11309, 212, true);
            WriteLiteral("                                                                <td><a class=\"VeSot\" style=\"color:blue;\" data-toggle=\"modal\" href=\"javascript:;\"><i class=\"fa fa-pencil-square-o\" aria-hidden=\"true\"></i></a></td>\r\n");
            EndContext();
#line 190 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                                            }
                                                            else
                                                            {

#line default
#line hidden
            BeginContext(11713, 137, true);
            WriteLiteral("                                                                <td><i class=\"fa fa-ban\" style=\"color:red\" aria-hidden=\"true\"></i></td>\r\n");
            EndContext();
#line 194 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                                            }
                                                    }
                                                    else
                                                    {

#line default
#line hidden
            BeginContext(12081, 129, true);
            WriteLiteral("                                                        <td><i class=\"fa fa-ban\" style=\"color:red\" aria-hidden=\"true\"></i></td>\r\n");
            EndContext();
#line 199 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                                    }

                                                

#line default
#line hidden
            BeginContext(12318, 54, true);
            WriteLiteral("\r\n                                                <td>");
            EndContext();
            BeginContext(12373, 1, false);
#line 203 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(i);

#line default
#line hidden
            EndContext();
            BeginContext(12374, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(12434, 10, false);
#line 204 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.MAHHK);

#line default
#line hidden
            EndContext();
            BeginContext(12444, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(12504, 9, false);
#line 205 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.MAKH);

#line default
#line hidden
            EndContext();
            BeginContext(12513, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(12573, 13, false);
#line 206 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.MAKH_EFF);

#line default
#line hidden
            EndContext();
            BeginContext(12586, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(12646, 9, false);
#line 207 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.CODE);

#line default
#line hidden
            EndContext();
            BeginContext(12655, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(12715, 16, false);
#line 208 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.TenNhanVien);

#line default
#line hidden
            EndContext();
            BeginContext(12731, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(12791, 12, false);
#line 209 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.NGAYSUA);

#line default
#line hidden
            EndContext();
            BeginContext(12803, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(12863, 8, false);
#line 210 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.PNR);

#line default
#line hidden
            EndContext();
            BeginContext(12871, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(12931, 9, false);
#line 211 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.SoVe);

#line default
#line hidden
            EndContext();
            BeginContext(12940, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(13000, 11, false);
#line 212 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.GiaMua);

#line default
#line hidden
            EndContext();
            BeginContext(13011, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(13071, 13, false);
#line 213 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.PhiDVMua);

#line default
#line hidden
            EndContext();
            BeginContext(13084, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(13144, 13, false);
#line 214 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.PhiDVBan);

#line default
#line hidden
            EndContext();
            BeginContext(13157, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(13217, 12, false);
#line 215 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.PhiHoan);

#line default
#line hidden
            EndContext();
            BeginContext(13229, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(13289, 14, false);
#line 216 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.ChietKhau);

#line default
#line hidden
            EndContext();
            BeginContext(13303, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(13363, 11, false);
#line 217 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.GHICHU);

#line default
#line hidden
            EndContext();
            BeginContext(13374, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(13434, 16, false);
#line 218 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.MAGIOITHIEU);

#line default
#line hidden
            EndContext();
            BeginContext(13450, 59, true);
            WriteLiteral("</td>\r\n                                                <td>");
            EndContext();
            BeginContext(13510, 19, false);
#line 219 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                               Write(item.NGUOIGIOITHIEU);

#line default
#line hidden
            EndContext();
            BeginContext(13529, 7, true);
            WriteLiteral("</td>\r\n");
            EndContext();
#line 220 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                                 if (item.TinhTrangEFF == false)
                                                {

#line default
#line hidden
            BeginContext(13669, 137, true);
            WriteLiteral("                                                    <td> <input id=\"TinhTrangEFF\" onclick=\"CheckStatusEFF(this);\" type=\"checkbox\"></td>\r\n");
            EndContext();
#line 223 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                                }
                                                else
                                                {

#line default
#line hidden
            BeginContext(13962, 133, true);
            WriteLiteral("                                                    <td><input id=\"TinhTrangEFF\" type=\"checkbox\" checked=\"checked\" disabled /></td>\r\n");
            EndContext();
#line 227 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                                }

#line default
#line hidden
            BeginContext(14146, 53, true);
            WriteLiteral("\r\n                                            </tr>\r\n");
            EndContext();
#line 230 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
                                        }
                                        i++;
                                    }
                                }
                            }

#line default
#line hidden
            BeginContext(14393, 147, true);
            WriteLiteral("                        </tbody>\r\n                    </table>\r\n                </div>\r\n            </div>\r\n        </div>\r\n    </div>\r\n</form>\r\n\r\n");
            EndContext();
#line 243 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
 if (ViewBag.msg != "" && ViewBag.msg != null)
{

#line default
#line hidden
            BeginContext(14591, 45, true);
            WriteLiteral("    <script charset=\"UTF-8\">\r\n        alert(\'");
            EndContext();
            BeginContext(14637, 21, false);
#line 246 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
          Write(Html.Raw(ViewBag.msg));

#line default
#line hidden
            EndContext();
            BeginContext(14658, 20, true);
            WriteLiteral("\');\r\n    </script>\r\n");
            EndContext();
#line 248 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\BaoCaoVe\DSVeSot.cshtml"
}

#line default
#line hidden
            BeginContext(14681, 3631, true);
            WriteLiteral(@"<script>
    $(""#gridVeSot .VeSot"").click(function () {
        var rowjQuery = $(this).closest(""tr"");
        var currentIndex = rowjQuery[0].rowIndex;
        var ID = String($(this).closest('tr').attr('id'));
        var MAHHK = document.getElementById(""gridVeSot"").rows[currentIndex].cells[2].innerHTML;
        var MAKH = document.getElementById(""gridVeSot"").rows[currentIndex].cells[3].innerHTML;
        var PNR = document.getElementById(""gridVeSot"").rows[currentIndex].cells[8].innerHTML;
        var SOVE = document.getElementById(""gridVeSot"").rows[currentIndex].cells[9].innerHTML;
        var GIAMUA = document.getElementById(""gridVeSot"").rows[currentIndex].cells[10].innerHTML;
        var PHIDVMUA = document.getElementById(""gridVeSot"").rows[currentIndex].cells[11].innerHTML;
        var PHIDVBAN = document.getElementById(""gridVeSot"").rows[currentIndex].cells[12].innerHTML;
        var PHIHOAN = document.getElementById(""gridVeSot"").rows[currentIndex].cells[13].innerHTML;
        var CHIETKHAU ");
            WriteLiteral(@"= document.getElementById(""gridVeSot"").rows[currentIndex].cells[14].innerHTML;
        var MAGIOITHIEU = document.getElementById(""gridVeSot"").rows[currentIndex].cells[16].innerHTML;
        var NGUOIGIOITHIEU = document.getElementById(""gridVeSot"").rows[currentIndex].cells[17].innerHTML;



        var ChiTietVeSot = {};
        ChiTietVeSot.ID = ID;
        ChiTietVeSot.MAKH = MAKH;
        ChiTietVeSot.PNR = PNR;
        ChiTietVeSot.SoVe = SOVE;
        ChiTietVeSot.GiaMua = GIAMUA;
        ChiTietVeSot.PhiDVMua = PHIDVMUA;
        ChiTietVeSot.PhiDVBan = PHIDVBAN;
        ChiTietVeSot.PhiHoan = PHIHOAN;
        ChiTietVeSot.ChietKhau = CHIETKHAU;
        ChiTietVeSot.MaGioiThieu = MAGIOITHIEU;
        ChiTietVeSot.NguoiGioiThieu = NGUOIGIOITHIEU;
        ChiTietVeSot.MAHHK = MAHHK;
        ChiTietVeSot.RowIndex = currentIndex;

        $.ajax({
            type: ""POST"",
            url: ""/KeToan/ChiTietVeSot"",
            data: {
                DataDetail: ChiTietVeSot
          ");
            WriteLiteral(@"  },
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
    function CheckStatusEFF(obj) {
        var table = document.getElementById(""gridVeSot"");
        var index = obj.parentNode.parentNode.rowIndex;

        var active = table.rows[index].cells[18].getElementsByTagName(""input"")[0].checked;
        var id = table.getElementsByTagName('tr')[index].id;

        $.ajax({
            type: ""POST"",
            url: ""/KeToan/KiemTraTinhTrangEFF"",
            data: {
                Active: active,
                RowID: id
            },
  ");
            WriteLiteral(@"          success: function (response) {
                if (response == true) {
                    alert(""Cập nhật thành công"");
                    return;
                } else {
                    alert(""Thất bại, xin vui lòng thử lại sau"");
                    return;
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Models.TongQuatMail> Html { get; private set; }
    }
}
#pragma warning restore 1591