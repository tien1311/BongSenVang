#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "2009d4c5c26a1f0736b0f78b527eb09a6946aa83"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_KyThuat_EditAirportCode), @"mvc.1.0.view", @"/Views/KyThuat/EditAirportCode.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/KyThuat/EditAirportCode.cshtml", typeof(AspNetCore.Views_KyThuat_EditAirportCode))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"2009d4c5c26a1f0736b0f78b527eb09a6946aa83", @"/Views/KyThuat/EditAirportCode.cshtml")]
    public class Views_KyThuat_EditAirportCode : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<BongSenVang.Services.Model.Request.AirportCodeRequest>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(62, 13, true);
            WriteLiteral("<style>\r\n    ");
            EndContext();
            BeginContext(76, 745, true);
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
</style>
<div class=""modal-dialog"">
    <!-- Modal content-->
    <div class=""modal-content"" style="" background: #2A3F54;"">
        <div class=""modal-header"">
            <button type=""button"" class=""close"" data-dismiss=""modal"">&times;</button>
            <h1 style=""color: #FFF; font-size: 16px;"">EditAirportCode</h1>
        </div>
        <div class=""modal-body"" style=""border-radius:8px; background-color:#fff;"">
");
            EndContext();
#line 28 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
             using (Html.BeginForm("SaveEditAirportCode", "KyThuat", new { i = 12 }, FormMethod.Post))
            {

#line default
#line hidden
            BeginContext(940, 109, true);
            WriteLiteral("                <div class=\"col-sm-6\">\r\n                    <div class=\"row\">\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 1049, "\"", 1055, 0);
            EndWriteAttribute();
            BeginContext(1056, 458, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">AirportCode</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" readonly id=""AirportCode"" name=""AirportCode"" placeholder=""AirportCode""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1514, "\"", 1540, 1);
#line 37 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 1522, Model.AirportCode, 1522, 18, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1541, 102, true);
            WriteLiteral(">\r\n                                        <input type=\"hidden\" class=\"form-control\" id=\"ID\" name=\"ID\"");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 1643, "\"", 1660, 1);
#line 38 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 1651, Model.ID, 1651, 9, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(1661, 185, true);
            WriteLiteral(">\r\n                                    </div>\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 1846, "\"", 1852, 0);
            EndWriteAttribute();
            BeginContext(1853, 449, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">AirportName</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" id=""AirportName"" name=""AirportName"" placeholder=""AirportName""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 2302, "\"", 2328, 1);
#line 48 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 2310, Model.AirportName, 2310, 18, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(2329, 185, true);
            WriteLiteral(">\r\n                                    </div>\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 2514, "\"", 2520, 0);
            EndWriteAttribute();
            BeginContext(2521, 437, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">Latitude</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" id=""Latitude"" name=""Latitude"" placeholder=""Latitude""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 2958, "\"", 2981, 1);
#line 58 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 2966, Model.Latitude, 2966, 15, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(2982, 185, true);
            WriteLiteral(">\r\n                                    </div>\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 3167, "\"", 3173, 0);
            EndWriteAttribute();
            BeginContext(3174, 441, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">Longitude</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" id=""Longitude"" name=""Longitude"" placeholder=""Longitude""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 3615, "\"", 3639, 1);
#line 68 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 3623, Model.Longitude, 3623, 16, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(3640, 185, true);
            WriteLiteral(">\r\n                                    </div>\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 3825, "\"", 3831, 0);
            EndWriteAttribute();
            BeginContext(3832, 461, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">TimeZoneOffset</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" id=""TimeZoneOffset"" name=""TimeZoneOffset"" placeholder=""TimeZoneOffset""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 4293, "\"", 4322, 1);
#line 78 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 4301, Model.TimeZoneOffset, 4301, 21, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(4323, 185, true);
            WriteLiteral(">\r\n                                    </div>\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 4508, "\"", 4514, 0);
            EndWriteAttribute();
            BeginContext(4515, 437, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">IataCode</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" id=""IataCode"" name=""IataCode"" placeholder=""IataCode""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 4952, "\"", 4975, 1);
#line 88 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 4960, Model.IataCode, 4960, 15, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(4976, 316, true);
            WriteLiteral(@">
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class=""col-sm-6"">
                    <div class=""row"">
                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 5292, "\"", 5298, 0);
            EndWriteAttribute();
            BeginContext(5299, 437, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">CityName</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" id=""CityName"" name=""CityName"" placeholder=""CityName""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 5736, "\"", 5759, 1);
#line 102 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 5744, Model.CityName, 5744, 15, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(5760, 185, true);
            WriteLiteral(">\r\n                                    </div>\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 5945, "\"", 5951, 0);
            EndWriteAttribute();
            BeginContext(5952, 437, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">CityCode</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" id=""CityCode"" name=""CityCode"" placeholder=""CityCode""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 6389, "\"", 6412, 1);
#line 112 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 6397, Model.CityCode, 6397, 15, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(6413, 185, true);
            WriteLiteral(">\r\n                                    </div>\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 6598, "\"", 6604, 0);
            EndWriteAttribute();
            BeginContext(6605, 449, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">CountryName</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" id=""CountryName"" name=""CountryName"" placeholder=""CountryName""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 7054, "\"", 7080, 1);
#line 122 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 7062, Model.CountryName, 7062, 18, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(7081, 185, true);
            WriteLiteral(">\r\n                                    </div>\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 7266, "\"", 7272, 0);
            EndWriteAttribute();
            BeginContext(7273, 449, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">CountryCode</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" id=""CountryCode"" name=""CountryCode"" placeholder=""CountryCode""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 7722, "\"", 7748, 1);
#line 132 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 7730, Model.CountryCode, 7730, 18, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(7749, 185, true);
            WriteLiteral(">\r\n                                    </div>\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 7934, "\"", 7940, 0);
            EndWriteAttribute();
            BeginContext(7941, 445, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">RegionCode</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" id=""RegionCode"" name=""RegionCode"" placeholder=""RegionCode""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 8386, "\"", 8411, 1);
#line 142 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 8394, Model.RegionCode, 8394, 17, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(8412, 185, true);
            WriteLiteral(">\r\n                                    </div>\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 8597, "\"", 8603, 0);
            EndWriteAttribute();
            BeginContext(8604, 449, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">Description</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <input type=""text"" class=""form-control"" id=""Description"" name=""Description"" placeholder=""Description""");
            EndContext();
            BeginWriteAttribute("value", " value=\"", 9053, "\"", 9079, 1);
#line 152 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
WriteAttributeValue("", 9061, Model.Description, 9061, 18, false);

#line default
#line hidden
            EndWriteAttribute();
            BeginContext(9080, 185, true);
            WriteLiteral(">\r\n                                    </div>\r\n                                </div>\r\n                            </div>\r\n                        </div>\r\n                        <label");
            EndContext();
            BeginWriteAttribute("for", " for=\"", 9265, "\"", 9271, 0);
            EndWriteAttribute();
            BeginContext(9272, 608, true);
            WriteLiteral(@" class=""col-sm-12 control-label"">&nbsp;</label>
                        <div class=""col-sm-12"">
                            <div class=""control-group"">
                                <div class=""controls"">
                                    <div class="" xdisplay_inputx form-group has-feedback"">
                                        <button type=""submit"" class=""btn btn-primary"">Save</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
");
            EndContext();
#line 169 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\KyThuat\EditAirportCode.cshtml"
            }

#line default
#line hidden
            BeginContext(9895, 34, true);
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<BongSenVang.Services.Model.Request.AirportCodeRequest> Html { get; private set; }
    }
}
#pragma warning restore 1591
