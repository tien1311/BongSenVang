#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "9c38345b663ae073d033bcca9b535c03ff41d28a"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Daily_DanhSachThanhVien), @"mvc.1.0.view", @"/Views/Daily/DanhSachThanhVien.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Daily/DanhSachThanhVien.cshtml", typeof(AspNetCore.Views_Daily_DanhSachThanhVien))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"9c38345b663ae073d033bcca9b535c03ff41d28a", @"/Views/Daily/DanhSachThanhVien.cshtml")]
    public class Views_Daily_DanhSachThanhVien : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Models.Danhsachmodel>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(41, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 3 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
  
    ViewData["Title"] = "Danh sách thành viên";
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(151, 7, true);
            WriteLiteral("<title>");
            EndContext();
            BeginContext(159, 17, false);
#line 7 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
  Write(ViewData["Title"]);

#line default
#line hidden
            EndContext();
            BeginContext(176, 127, true);
            WriteLiteral("</title>\r\n<div>\r\n    <h2>DANH SÁCH THÀNH VIÊN </h2>\r\n    <div class=\"x_panel\">\r\n        <div class=\"x_content\">\r\n            \r\n");
            EndContext();
#line 13 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
             using (Html.BeginForm("DanhSachThanhVien", "Daily", new { i = 12 }, FormMethod.Post))
            { 

#line default
#line hidden
            BeginContext(419, 401, true);
            WriteLiteral(@"                <div class=""row"">

                    <div class=""col-md-4 form-group"">
                        <div class=""row"">
                            <label class=""col-xs-4"">
                                Tên đại lí
                            </label>
                            <div class=""col-xs-8"" style=""padding-right:0px"">

                                <input type=""text""");
            EndContext();
            BeginWriteAttribute("value", " value=\'", 820, "\'", 842, 1);
#line 24 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
WriteAttributeValue("", 828, ViewBag.TenDL, 828, 14, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(843, 512, true);
            WriteLiteral(@" class=""form-control"" id=""TenDL"" name=""TenDL"" />

                            </div>
                        </div>

                    </div>
                    <div class=""col-md-4 form-group"">
                        <div class=""row"">
                            <label class=""col-xs-4"">
                                Người LH
                            </label>
                            <div class=""col-xs-8"" style=""padding-right:0px"">

                                <input type=""text""");
            EndContext();
            BeginWriteAttribute("value", " value=\'", 1355, "\'", 1379, 1);
#line 37 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
WriteAttributeValue("", 1363, ViewBag.NguoiLH, 1363, 16, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1380, 517, true);
            WriteLiteral(@" class=""form-control"" id=""NguoiLH"" name=""NguoiLH"" />

                            </div>
                        </div>

                    </div>


                    <div class=""col-md-4 form-group"">
                        <div class=""row"">
                            <label class=""col-xs-4"">
                                Mã KH
                            </label>
                            <div class=""col-xs-8"" style=""padding-right:0px"">

                                <input type=""text""");
            EndContext();
            BeginWriteAttribute("value", " value=\'", 1897, "\'", 1918, 1);
#line 52 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
WriteAttributeValue("", 1905, ViewBag.MaKH, 1905, 13, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1919, 526, true);
            WriteLiteral(@" class=""form-control"" id=""MaKH"" name=""MaKH"" />

                            </div>
                        </div>

                    </div>
               

                    <div class=""col-md-4 form-group"">
                        <div class=""row"">
                            <label class=""col-xs-4"">
                                Email
                            </label>
                            <div class=""col-xs-8"" style=""padding-right:0px"">

                                <input type=""text""");
            EndContext();
            BeginWriteAttribute("value", " value=\'", 2445, "\'", 2467, 1);
#line 67 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
WriteAttributeValue("", 2453, ViewBag.Email, 2453, 14, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(2468, 515, true);
            WriteLiteral(@" class=""form-control"" id=""Email"" name=""Email"" />

                            </div>
                        </div>

                    </div>
                    <div class=""col-md-4 form-group"" >
                        <div class=""row"">
                            <label class=""col-xs-4"">
                                Điện thoại
                            </label>
                            <div class=""col-xs-8"" style=""padding-right:0px"">

                                <input type=""text""");
            EndContext();
            BeginWriteAttribute("value", " value=\'", 2983, "\'", 3005, 1);
#line 80 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
WriteAttributeValue("", 2991, ViewBag.Phone, 2991, 14, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(3006, 598, true);
            WriteLiteral(@" class=""form-control"" id=""Phone"" name=""Phone"" />

                            </div>
                        </div>
                    </div>
                    <div class=""col-md-4 form-group"" >
                        <div class=""row"">
                            <label class=""col-xs-4"">
                                Kinh doanh
                            </label>
                            <div class=""col-xs-8"" style=""padding-right:0px"">
                                <select id=""ChuDe"" name=""ChuDe"" asp-for=""ChuDe"" class=""select2_single form-control"" onchange=""getTo()"">
");
            EndContext();
#line 92 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                                     foreach (var item in Model.ListTen)
                                    {

#line default
#line hidden
            BeginContext(3717, 47, true);
            WriteLiteral("                                        <option");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 3764, "\"", 3783, 1);
#line 94 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
WriteAttributeValue("", 3772, item.RowID, 3772, 11, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(3784, 16, true);
            WriteLiteral(" class=\"tieude\">");
            EndContext();
            BeginContext(3801, 8, false);
#line 94 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                                                                              Write(item.Ten);

#line default
#line hidden
            EndContext();
            BeginContext(3809, 11, true);
            WriteLiteral("</option>\r\n");
            EndContext();
#line 95 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                                    }

#line default
#line hidden
            BeginContext(3859, 682, true);
            WriteLiteral(@"                                </select>
                            </div>
                        </div>
                    </div>               
                    <div class=""col-md-12 form-group"" >
                        <div class=""row"">
                            <div style=""text-align:right;"">
                                <input type=""submit"" class=""btn btn-primary"" value=""Tìm Kiếm"" name=""searchBtn"" />
                                <input type=""submit"" class=""btn btn-success"" value=""Làm mới"" name=""resetBtn"" />
                            </div>
                        </div>
                    </div>
                </div>                   
");
            EndContext();
#line 109 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
            }           

#line default
#line hidden
            BeginContext(4567, 971, true);
            WriteLiteral(@"        </div>
    </div> 
    <br />
    <div class=""table-responsive"" style=""font-size:12px;"">
        <table id=""gridTable"" class=""table table-striped jambo_table bulk_action"">
            <thead>
                <tr class=""headings"">
                    <th class=""column-title"">STT</th>
                    <th class=""column-title"">Ten đại lý</th>
                    <th class=""column-title"">Người đại diện</th>
                    <th class=""column-title"">Tài khoản</th>
                    <th class=""column-title"">Email</th>
                    <th class=""column-title"">Địa chỉ</th>
                    <th class=""column-title"">
                        Kích hoạt
                    </th>
                    <th class=""column-title"">
                        Khôi phục mật khẩu
                    </th>
                    <th style=""display:none"" class=""column-title""></th>
                </tr>
            </thead>
            <tbody>
");
            EndContext();
#line 133 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                  int i = 1;

#line default
#line hidden
#line 134 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                 if (Model != null)
                {
                    

#line default
#line hidden
#line 136 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                     if (Model.member != null)
                    {
                        

#line default
#line hidden
#line 138 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                         foreach (var item in Model.member)
                        {

#line default
#line hidden
            BeginContext(5784, 19, true);
            WriteLiteral("                <tr");
            EndContext();
            BeginWriteAttribute("id", " id=\"", 5803, "\"", 5823, 1);
#line 140 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
WriteAttributeValue("", 5808, item.member_id, 5808, 15, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(5824, 74, true);
            WriteLiteral(" class=\"even pointer\">\r\n                    <td style=\"text-align:center\">");
            EndContext();
            BeginContext(5899, 1, false);
#line 141 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                                             Write(i);

#line default
#line hidden
            EndContext();
            BeginContext(5900, 30, true);
            WriteLiteral("</td>\r\n                    <td");
            EndContext();
            BeginWriteAttribute("class", " class=\"", 5930, "\"", 5938, 0);
            EndWriteAttribute();
            BeginContext(5939, 65, true);
            WriteLiteral("><a class=\"Chitiet\" data-target=\"#openPopup\" href=\"javascript:;\">");
            EndContext();
            BeginContext(6005, 19, false);
#line 142 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                                                                                            Write(item.member_company);

#line default
#line hidden
            EndContext();
            BeginContext(6024, 34, true);
            WriteLiteral("</a></td>\r\n                    <td");
            EndContext();
            BeginWriteAttribute("class", " class=\"", 6058, "\"", 6066, 0);
            EndWriteAttribute();
            BeginContext(6067, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(6069, 16, false);
#line 143 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                            Write(item.member_name);

#line default
#line hidden
            EndContext();
            BeginContext(6085, 31, true);
            WriteLiteral(" </td>\r\n                    <td");
            EndContext();
            BeginWriteAttribute("class", " class=\"", 6116, "\"", 6124, 0);
            EndWriteAttribute();
            BeginContext(6125, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(6127, 16, false);
#line 144 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                            Write(item.member_code);

#line default
#line hidden
            EndContext();
            BeginContext(6143, 30, true);
            WriteLiteral("</td>\r\n                    <td");
            EndContext();
            BeginWriteAttribute("class", " class=\"", 6173, "\"", 6181, 0);
            EndWriteAttribute();
            BeginContext(6182, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(6184, 17, false);
#line 145 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                            Write(item.member_email);

#line default
#line hidden
            EndContext();
            BeginContext(6201, 30, true);
            WriteLiteral("</td>\r\n                    <td");
            EndContext();
            BeginWriteAttribute("class", " class=\"", 6231, "\"", 6239, 0);
            EndWriteAttribute();
            BeginContext(6240, 1, true);
            WriteLiteral(">");
            EndContext();
            BeginContext(6242, 19, false);
#line 146 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                            Write(item.member_address);

#line default
#line hidden
            EndContext();
            BeginContext(6261, 9, true);
            WriteLiteral("</td>\r\n\r\n");
            EndContext();
#line 148 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                     if (item.member_isactive == "1")
                    {

#line default
#line hidden
            BeginContext(6348, 187, true);
            WriteLiteral("                        <td>\r\n\r\n                            <input id=\"ActiveUser\" onclick=\"CheckActiveMember(this);\" type=\"checkbox\" checked=\"checked\">\r\n\r\n                        </td>\r\n");
            EndContext();
#line 155 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                    }
                    else
                    {

#line default
#line hidden
            BeginContext(6607, 169, true);
            WriteLiteral("                        <td>\r\n\r\n                            <input id=\"ActiveUser\" onclick=\"CheckActiveMember(this);\" type=\"checkbox\">\r\n\r\n                        </td>\r\n");
            EndContext();
#line 163 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                    }

#line default
#line hidden
            BeginContext(6799, 68, true);
            WriteLiteral("                    \r\n                    <td><input type=\"checkbox\"");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 6867, "\"", 6875, 0);
            EndWriteAttribute();
            BeginContext(6876, 103, true);
            WriteLiteral(" onclick=\"Resetpass(this);\"  class=\"bi bi-check\"></td>\r\n\r\n                    <td style=\"display:none\">");
            EndContext();
            BeginContext(6980, 14, false);
#line 167 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                                        Write(item.member_id);

#line default
#line hidden
            EndContext();
            BeginContext(6994, 30, true);
            WriteLiteral("</td>\r\n                </tr>\r\n");
            EndContext();
#line 169 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                            i++;
                        }

#line default
#line hidden
#line 170 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                         
                    }
                    else
                    {

#line default
#line hidden
            BeginContext(7157, 394, true);
            WriteLiteral(@"                        <tr>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td></td>
                            <td style=""display:none""></td>
                        </tr>
");
            EndContext();
#line 184 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                    }

#line default
#line hidden
#line 184 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                     
                }
                else
                {

#line default
#line hidden
            BeginContext(7634, 354, true);
            WriteLiteral(@"                    <tr>
                        <td></td>
                        <td></td>
                        <td></td>
                        <td></td>
                        <td></td>
                        <td></td>
                        <td></td>
                        <td style=""display:none""></td>
                    </tr>
");
            EndContext();
#line 198 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                }

#line default
#line hidden
            BeginContext(8007, 4004, true);
            WriteLiteral(@"            </tbody>
        </table>
    </div>



    <style>
        .all-browsers {
            margin: 0;
            border: 1px solid #D3D3D3;
            background: white;
        }

        .browser {
            background: #AAAAAA;
        }

        .browser {
            margin: 0;
            font-size: 100%;
        }
       

    </style>
    <script>
        $(""#gridTable .Chitiet"").click(function () {

            /*var index = $('#gridVeHoan tr').index($(this).closest('tr'));*/
            var id = String($(this).closest('tr').attr('id'));

            $.ajax({
                type: ""POST"",
                url: ""/Daily/ChiTietMember"",
                data: { khoachinh: id },
                success: function (response) {
                    $('#openPopup').html(response);
                    $('#openPopup').modal({
                        backdrop: 'static',
                        keyboard: false,
                        show: true
                 ");
            WriteLiteral(@"   });
                },
                failure: function (response) {
                    alert(response.responseText);
                },
                error: function (response) {
                    alert(response.responseText);
                }
            });
        });
        function CheckActiveMember(obj) {
            var table = document.getElementById(""gridTable"");
            var index = obj.parentNode.parentNode.rowIndex;
            var active = """";
            var n = table.rows[index].cells[6].getElementsByTagName(""input"")[0].checked;
            var z = table.getElementsByTagName('tr')[index].id;
         
           
            if (n == true) {
                active = 1;
            }
            else {
                active = 0;
            }
            $.ajax({
                    type: ""POST"",
                    url: ""/Daily/ActiveMember"",
                    data: {
                        Active: active,
                        RowID: z
       ");
            WriteLiteral(@"             },
                success: function (response) {
                    if (response == true) {
                        document.getElementById(""ActiveUser"").setAttribute(""checked"", ""checked"");
                        alert(""Ngừng kích hoạt thành công"");
                        return;
                    } else {
                        document.getElementById(""ActiveUser"").removeAttribute(""checked"");
                        alert(""Kích hoạt thành công"");
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
        function Resetpass(obj) {
            var table = document.getElementById(""gridTable"");
            var index = obj.parentNode.parentNode.rowIndex;          
       ");
            WriteLiteral(@"     var z = table.getElementsByTagName('tr')[index].id;
        
            $.ajax({
                type: ""POST"",
                url: ""/Daily/ResetPass"",
                data: {                  
                    RowID: z
                },
                success: function (response) {
                    if (response == true) {
                        alert(""Khôi phục thành công"");
                        return;
                    } else {                    
                        alert(""Khôi phục thất bại "");
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
          
    </script>
    <div class=""row"">
");
            EndContext();
#line 320 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
         if (ViewBag.thongbao != null)
        {

#line default
#line hidden
            BeginContext(12062, 69, true);
            WriteLiteral("            <script charset=\"UTF-8\">\r\n\r\n                      alert(\'");
            EndContext();
            BeginContext(12132, 26, false);
#line 324 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"
                        Write(Html.Raw(ViewBag.thongbao));

#line default
#line hidden
            EndContext();
            BeginContext(12158, 28, true);
            WriteLiteral("\');\r\n            </script>\r\n");
            EndContext();
#line 326 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\Daily\DanhSachThanhVien.cshtml"

        }

#line default
#line hidden
            BeginContext(12199, 20, true);
            WriteLiteral("    </div>\r\n</div>\r\n");
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Models.Danhsachmodel> Html { get; private set; }
    }
}
#pragma warning restore 1591
