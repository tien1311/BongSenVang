#pragma checksum "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\PhongVe\Index_BK.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "f68a1497f991c4cea36fda014889859670504892"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_PhongVe_Index_BK), @"mvc.1.0.view", @"/Views/PhongVe/Index_BK.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/PhongVe/Index_BK.cshtml", typeof(AspNetCore.Views_PhongVe_Index_BK))]
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
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"f68a1497f991c4cea36fda014889859670504892", @"/Views/PhongVe/Index_BK.cshtml")]
    public class Views_PhongVe_Index_BK : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(0, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 2 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\PhongVe\Index_BK.cshtml"
  
    ViewData["Title"] = "Phòng vé";
    Layout = "~/Views/Shared/MasterLayout.cshtml";

#line default
#line hidden
            BeginContext(98, 7, true);
            WriteLiteral("<title>");
            EndContext();
            BeginContext(106, 17, false);
#line 6 "D:\EnViet\SourceAzure\BongSenVang\DaiLy_EV\Views\PhongVe\Index_BK.cshtml"
  Write(ViewData["Title"]);

#line default
#line hidden
            EndContext();
            BeginContext(123, 1426, true);
            WriteLiteral(@"</title>
<style>
    .container-login100 {
        width: 100%;
        min-height: 100vh;
        flex-wrap: wrap;
        justify-content: center;
        align-items: center;
        padding: 15px;
        background-position: center;
        background-size: cover;
        background-repeat: no-repeat;
    }

    .img-responsive {
        border-radius: 7px;
        margin-bottom: 30px;
    }

    .logo {
        text-align: center;
        margin-top: 30px;
        margin-bottom: 50px;
    }

    .container-login100 {
        background-image: url('/images/2.png');
    }

    .container-content {
        background: #fff;
        border-radius: 5px;
        padding: 0px;
        text-align: justify;
    }

    .content-iframe {
        margin: auto;
        width: 100%;
    }

    .nav-tabs > li.active > a, .nav-tabs > li.active > a:focus, .nav-tabs > li.active > a:hover {
        font-weight: bold;
    }

    .nav > li > a:focus, .nav > li > a:hover {
      ");
            WriteLiteral(@"  color: #000 !important;
    }

    .content-iframe iframe {
        height: 800px;
        width: 100%;
        border-radius: 7px;
    }

    .tab-content > .active {
        opacity: 1;
    }

    .btn-BSP {
        color: #fff;
        background-color: #6c0678;
        border-color: #6c0678;
    }

    .nav > li > a {
        padding: 8px 13px 8px !important;
    }

    ");
            EndContext();
            BeginContext(1550, 373, true);
            WriteLiteral(@"@media (max-width: 768px) {
        .logo {
            text-align: center;
            margin-top: 0px;
            margin-bottom: 30px;
        }

        .container-login100 {
            background-image: url('/images/5.jpg');
            background-position: inherit;
        }

        .content-iframe {
            width: 100%;
        }
    }

    ");
            EndContext();
            BeginContext(1924, 193, true);
            WriteLiteral("@media (min-width: 768px) {\r\n        .modal-dialog {\r\n            width: 100%;\r\n            margin: auto;\r\n        }\r\n    }\r\n</style>\r\n<div class=\"limiter\">\r\n    <div class=\"container-login100\"");
            EndContext();
            BeginWriteAttribute("style", " style=\"", 2117, "\"", 2125, 0);
            EndWriteAttribute();
            BeginContext(2126, 2880, true);
            WriteLiteral(@">
        <div class=""content-iframe"">
            <div class=""modal-dialog"">
                <!-- Modal content-->
                <div class=""modal-content"">
                    <ul class=""nav nav-tabs"" id=""myTab"" role=""tablist"" style=""margin-bottom:10px;"">
                        <li class=""nav-item active"">
                            <a class=""btn btn-success"" id=""Hang-tab"" data-toggle=""tab"" href=""#Hang"" role=""tab"" aria-controls=""Hang"" aria-selected=""false"">NEWS</a>
                        </li>
                        <li class=""nav-item "">
                            <a class=""btn btn-info"" id=""SGN-tab"" data-toggle=""tab"" href=""#SGN"" role=""tab"" aria-controls=""SGN"" aria-selected=""true"">SGN</a>
                        </li>
                        <li class=""nav-item "">
                            <a class=""btn btn-danger"" id=""DAD-tab"" data-toggle=""tab"" href=""#DAD"" role=""tab"" aria-controls=""DAD"" aria-selected=""true"">DAD</a>
                        </li>
                        <li class=""na");
            WriteLiteral(@"v-item "">
                            <a class=""btn btn-dark"" id=""HAN-tab"" data-toggle=""tab"" href=""#HAN"" role=""tab"" aria-controls=""HAN"" aria-selected=""true"">HAN</a>
                        </li>
                        <li class=""nav-item "">
                            <a class=""btn btn-warning"" id=""CA-tab"" data-toggle=""tab"" href=""#CA"" role=""tab"" aria-controls=""CA"" aria-selected=""true"">CA</a>
                        </li>
                        <li class=""nav-item "">
                            <a class=""btn btn-primary"" id=""CC-tab"" data-toggle=""tab"" href=""#CC"" role=""tab"" aria-controls=""CC"" aria-selected=""true"">CC</a>
                        </li>
                        <li class=""nav-item "">
                            <a class=""btn btn-success"" id=""Q-tab"" data-toggle=""tab"" href=""#Q"" role=""tab"" aria-controls=""Q"" aria-selected=""true"">QUEUE</a>
                        </li>

                        <li class=""nav-item"">
                            <a class=""btn btn-info"" id=""QD-tab"" data-toggle");
            WriteLiteral(@"=""tab"" href=""#QD"" role=""tab"" aria-controls=""QD"" aria-selected=""true"">QUY ĐỊNH</a>
                        </li>
                        <li class=""nav-item"">
                            <a class=""btn btn-danger"" id=""BK-tab"" data-toggle=""tab"" href=""#BK"" role=""tab"" aria-controls=""BK"" aria-selected=""true"">PHÒNG VÉ</a>
                        </li>
                        <li class=""nav-item "">
                            <a class=""btn btn-dark"" id=""LH-tab"" data-toggle=""tab"" href=""#LH"" role=""tab"" aria-controls=""LH"" aria-selected=""true"">LỊCH HỌC</a>
                        </li>
                        <li class=""nav-item "">
                            <a class=""btn btn-warning"" id=""FAM-tab"" data-toggle=""tab"" href=""#FAM"" role=""tab"" aria-controls=""FAM"" aria-selected=""true"">FARMTRIP</a>
                        </li>
");
            EndContext();
            BeginContext(5250, 6944, true);
            WriteLiteral(@"                    </ul>
                    <div class=""modal-body"">
                        <div class=""tab-content popup"" id=""myTabContent"">
                            <div class=""tab-pane fade active"" id=""Hang"" role=""tabpanel"" aria-labelledby=""Hang-tab"">
                                <div class=""row"">
                                    <div class=""col-xs-12 container-content"">
                                        <iframe id=""IF2"" src=""https://docs.google.com/spreadsheets/d/e/2PACX-1vTSEmku_LgUr84_cRh3hHYo03MAnVFVgBnzM9L9EE1HqGVYUdkLcCM2DBSVq0HKfFCFhUCX_UkRTsP3/pubhtml?gid=0&amp;single=true&amp;widget=true&amp;headers=false""></iframe>
                                    </div>
                                </div>
                            </div>
                            <div class=""tab-pane fade "" id=""SGN"" role=""tabpanel"" aria-labelledby=""SGN-tab"">
                                <div class=""row"">
                                    <div class=""col-xs-12 container-content"">
    ");
            WriteLiteral(@"                                    <iframe src=""https://docs.google.com/spreadsheets/d/e/2PACX-1vSnqzo4aunCyXlQ3rSZCNcJVW8nAnij9iYv4QOPdG4SAf7fZsFvNdFzLB4RIdGNtzuznz1aDhdLvY_l/pubhtml?gid=757147068&amp;single=true&amp;widget=true&amp;headers=false""></iframe>
                                    </div>
                                </div>
                            </div>
                            <div class=""tab-pane fade"" id=""DAD"" role=""tabpanel"" aria-labelledby=""DAD-tab"">
                                <div class=""row"">
                                    <div class=""col-xs-12 container-content"">
                                        <iframe src=""https://docs.google.com/spreadsheets/d/e/2PACX-1vSnqzo4aunCyXlQ3rSZCNcJVW8nAnij9iYv4QOPdG4SAf7fZsFvNdFzLB4RIdGNtzuznz1aDhdLvY_l/pubhtml?gid=1925200341&amp;single=true&amp;widget=true&amp;headers=false""></iframe>
                                    </div>
                                </div>
                            </div>
                   ");
            WriteLiteral(@"         <div class=""tab-pane fade"" id=""HAN"" role=""tabpanel"" aria-labelledby=""HAN-tab"">
                                <div class=""row"">
                                    <div class=""col-xs-12 container-content"">
                                        <iframe src=""https://docs.google.com/spreadsheets/d/e/2PACX-1vSnqzo4aunCyXlQ3rSZCNcJVW8nAnij9iYv4QOPdG4SAf7fZsFvNdFzLB4RIdGNtzuznz1aDhdLvY_l/pubhtml?gid=209059366&amp;single=true&amp;widget=true&amp;headers=false""></iframe>
                                    </div>
                                </div>
                            </div>
                            <div class=""tab-pane fade"" id=""CA"" role=""tabpanel"" aria-labelledby=""CA-tab"">
                                <div class=""row"">
                                    <div class=""col-xs-12 container-content"">
                                        <iframe src=""https://docs.google.com/spreadsheets/d/e/2PACX-1vSnqzo4aunCyXlQ3rSZCNcJVW8nAnij9iYv4QOPdG4SAf7fZsFvNdFzLB4RIdGNtzuznz1aDhdLvY_l/pub");
            WriteLiteral(@"html?gid=1700233071&amp;single=true&amp;widget=true&amp;headers=false""></iframe>
                                    </div>
                                </div>
                            </div>
                            <div class=""tab-pane fade"" id=""CC"" role=""tabpanel"" aria-labelledby=""CC-tab"">
                                <div class=""row"">
                                    <div class=""col-xs-12 container-content"">
                                        <iframe src=""https://docs.google.com/spreadsheets/d/e/2PACX-1vSnqzo4aunCyXlQ3rSZCNcJVW8nAnij9iYv4QOPdG4SAf7fZsFvNdFzLB4RIdGNtzuznz1aDhdLvY_l/pubhtml?gid=200428840&amp;single=true&amp;widget=true&amp;headers=false""></iframe>
                                    </div>
                                </div>
                            </div>
                            <div class=""tab-pane fade"" id=""Q"" role=""tabpanel"" aria-labelledby=""Q-tab"">
                                <div class=""row"">
                                    <div class");
            WriteLiteral(@"=""col-xs-12 container-content"">
                                        <iframe src=""https://docs.google.com/spreadsheets/d/e/2PACX-1vSnqzo4aunCyXlQ3rSZCNcJVW8nAnij9iYv4QOPdG4SAf7fZsFvNdFzLB4RIdGNtzuznz1aDhdLvY_l/pubhtml?gid=526321010&amp;single=true&amp;widget=true&amp;headers=false""></iframe>
                                    </div>
                                </div>
                            </div>
                            <div class=""tab-pane fade"" id=""QD"" role=""tabpanel"" aria-labelledby=""QD-tab"">
                                <div class=""row"">
                                    <div class=""col-xs-12 container-content"">
                                        <iframe src=""https://docs.google.com/spreadsheets/d/e/2PACX-1vTSEmku_LgUr84_cRh3hHYo03MAnVFVgBnzM9L9EE1HqGVYUdkLcCM2DBSVq0HKfFCFhUCX_UkRTsP3/pubhtml?gid=150335414&amp;single=true&amp;widget=true&amp;headers=false""></iframe>
                                    </div>
                                </div>
                     ");
            WriteLiteral(@"       </div>
                            <div class=""tab-pane fade"" id=""BK"" role=""tabpanel"" aria-labelledby=""BK-tab"">
                                <div class=""row"">
                                    <div class=""col-xs-12 container-content"">
                                        <iframe src=""https://docs.google.com/document/d/e/2PACX-1vSW_JmfBejBS_m3MEii2_PllptatICb6UP1S8FfY9zB3ne30dC12m4MNlbSkAw2mjxaOhnKsrUsRPvu/pub?embedded=true""></iframe>
                                    </div>
                                </div>
                            </div>
                            <div class=""tab-pane fade"" id=""LH"" role=""tabpanel"" aria-labelledby=""LH-tab"">
                                <div class=""row"">
                                    <div class=""col-xs-12 container-content"">
                                        <iframe src=""https://docs.google.com/spreadsheets/d/e/2PACX-1vSnqzo4aunCyXlQ3rSZCNcJVW8nAnij9iYv4QOPdG4SAf7fZsFvNdFzLB4RIdGNtzuznz1aDhdLvY_l/pubhtml?gid=1723227470&amp;si");
            WriteLiteral(@"ngle=true&amp;widget=true&amp;headers=false""></iframe>
                                    </div>
                                </div>
                            </div>
                            <div class=""tab-pane fade"" id=""FAM"" role=""tabpanel"" aria-labelledby=""FAM-tab"">
                                <div class=""row"">
                                    <div class=""col-xs-12 container-content"">
                                        <iframe src=""https://docs.google.com/spreadsheets/d/e/2PACX-1vSnqzo4aunCyXlQ3rSZCNcJVW8nAnij9iYv4QOPdG4SAf7fZsFvNdFzLB4RIdGNtzuznz1aDhdLvY_l/pubhtml?gid=1249332348&amp;single=true&amp;widget=true&amp;headers=false""></iframe>
                                    </div>
                                </div>
                            </div>
");
            EndContext();
            BeginContext(12582, 261, true);
            WriteLiteral(@"                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    var h = window.innerHeight;
    document.getElementById(""IF2"").style.height = h - 160 + ""px"";
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
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<dynamic> Html { get; private set; }
    }
}
#pragma warning restore 1591
