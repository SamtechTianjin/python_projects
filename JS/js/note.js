// javascript基本数据类型
var name="Sam",age=18;
name
//"Sam"
age
//18
typeof(name);
//"string"
typeof(age);
//"number"
parseInt("123456");
//123456
var name="Alex     ";
name.trim();
//"Alex"
var name="Shevchenko";
name.charAt(3);
//"v"
name.substring(1,5);
//"hevc"
name.indexOf("k");
//8
name.length;
//10
Boolean("1");
//true
Boolean("0");
//true
Boolean(0);
//false
var li = [11,22,33];
li
//(3) [11, 22, 33]
var li = Array(11,22,33);
li
//(3) [11, 22, 33]
li.unshift("OO");
//4
li
//(4) ["OO", 11, 22, 33]
li.push("PP");
//5
li
//(5) ["OO", 11, 22, 33, "PP"]
li.splice(1,0,"Sam");   // 0是固定值
//[]
li
//(6) ["OO", "Sam", 11, 22, 33, "PP"]
li.pop();
//"PP"
li.shift();
//"OO"
li.splice(1,3);
//(3) [11, 22, 33]
li
//["Sam"]
var li = Array("sam","male",11,22,33);
//undefined
li
//(5) ["sam", "male", 11, 22, 33]
li.slice(0,3);
//(3) ["sam", "male", 11]
var a = [11,22,33,44];
//undefined
var b = Array(55,66,77,88);
//undefined
c = a.concat(b);
//(8) [11, 22, 33, 44, 55, 66, 77, 88]
c.reverse();
//(8) [88, 77, 66, 55, 44, 33, 22, 11]
c.join("-");
//"88-77-66-55-44-33-22-11"
dic = {"name": "Sam"};
//{name: "Sam"}
tmp = JSON.stringify(dic);
//"{"name":"Sam"}"
JSON.parse(tmp);
//{name: "Sam"}
var hello;
hello
//undefined
Boolean(null);
//false
Boolean(undefined);
//false
li
//(5) [33, 22, 11, "male", "sam"]
for(var item in li){console.log(item);}
0
1
2
3
4
// 索引

for(var item in dic){console.log(item);}
name
age
// 键值

for(var i=0;i<5;i++){console.log(i);}
0
1
2
3
4

for(var i=0;i<li.length;i++){console.log(li[i]);}
33
22
11
male
sam

for(var key in dic){
    console.log(dic[key]);
}
Sam
18

while
continue
break

if(xxx){

}else if(xxx){

}else{

}

var name = 5;
switch(name){
    case 1:
        console.log("111");
        break;
    case 2:
        console.log("222");
        break;
    default:
        console.log("ddd");
}



try{
}catch(e){
}finally{
}


// 普通函数
function func(arg){
    console.log(arg);
}

// 匿名函数
var f=function func(arg){
    console.log(arg);
}


// 自执行函数
(function(arg){
    console.log("name:",arg);
})("Sam");
//name: Sam









/*
<h1>INDEX</h1>
<h1>INDEX</h1>
<h1>INDEX</h1>

<div>
    <div id="n1">c1</div>
</div>

<ul>
    <li>123</li>
    <li>123</li>
    <li>123</li>
</ul>

<div>
    <div class="c1">a</div>
    <div class="c1">b</div>
    <div class="c1">c</div>
</div>

<form action="">
    username: <input type="text" name="username" value="sam">
    password: <input type="text" name="password" value="111111">
</form>
*/

// innerText获得值 标签中间文本内容
// innerHTML 标签中间内容
var nid = document.getElementById("n1");
nid.innerText = "alex";

var lis = document.getElementsByTagName("li");
for(var i in lis){
    var item = lis[i];
    item.innerText = i;
}

var lis = document.getElementsByClassName("c1");
for(var i in lis){
    var item = lis[i];
    item.innerText = i;
}

// value获得值 (input,option,textarea)
var username = document.getElementsByName("username")[0];
var password = document.getElementsByName("password")[0];
console.log(username.value,password.value);





/*
<div>
    <div id="num">1</div>
    <input type="button" value="+1" onclick="ADD();">
</div>
*/

function ADD() {
    var nid = document.getElementById("num");
    var text = nid.innerText;
    text = parseInt(text);
    text += 1;
    nid.innerText = text;
}






/*
<div>
    <input type="text" id="nnn">
    <input type="button" value="获取值" onclick="GetValue();">
</div>
*/

function GetValue() {
    var obj = document.getElementById("nnn");
    alert(obj.value);
    obj.value = "";
}






/*
<select name="select" id="aaa">
    <option value="1">Shanghai</option>
    <option value="2">Beijing</option>
    <option value="3">Shenzhen</option>
</select>
<input type="button" value="获取值" onclick="GetValue();">
*/

function GetValue() {
    var obj = document.getElementById("aaa");
    alert(obj.value);
    obj.value = 2;
}






/*
<input type="text" id="search" value="请输入关键字" onfocus="Focus();" onblur="Blur();">
*/

// onfocus,onblur
function Focus() {
        var nid = document.getElementById("search");
        console.log(nid)
        var value = nid.value;
        console.log(value);
        if(value == "请输入关键字"){
            nid.value = "";
        }
    }
function Blur() {
    var nid = document.getElementById("search");
    var value = nid.value;
    if(!value.trim()){
        nid.value = "请输入关键字";
    }
}







/*
<div id="container">
        <a href="http://www.baidu.com" onclick="return AddElement();">添加</a>
</div>
*/

//先执行自定义函数 再执行默认操作
//如果只执行自定义函数，可以使自定义函数返回false即可
<script type="text/javascript">
    function AddElement() {
        alert("Add");
        return false;
}






/*
<div id="container">
</div>
<a href="http://www.baidu.com" onclick="return AddElement();">添加</a>
*/

//标签内添加标签
function AddElement() {
    var nid = document.getElementById("container");
    var tag = "<input type='text'>";
    nid.innerHTML = tag;
    return false;
}
function AddElement() {
    var createObj = document.createElement("a");
    createObj.href = "http://www.baidu.com";
    createObj.innerText = "Baidu";
    createObj.id = "baiduatag"
    var nid = document.getElementById("container");
    nid.appendChild(createObj);
    return false;
}
//设定标签属性
//默认属性 eg: nid.id, nid.className, nid.style.backgroundColor
//自定义属性
//setAttribute可以适用于所有属性
var nid = document.getElementById("container");
nid.className = "C1";
nid.style.backgroundColor = "red";
nid.style.fontSize = "12px";
nid.setAttribute("name", "sam");
nid.setAttribute("Hahaha", "xxxooo");
console.log(nid);
//<div id="container" class="C1" name="sam" hahaha="xxxooo" style="background-color: blue; font-size: 12px;">Container</div>
nid.getAttribute("name");
//"sam"





/*
<form id="submit" action="https://www.sogou.com/web" method="get">
    <input type="text" name="query">
    <div onclick="Submit();">提交</div>
</form>
*/
//提交表单
//使用input的submit进行提交
//创建函数提交
function Submit() {
    var nid = document.getElementById("submit");
    nid.submit();
}






/*
<form id="submit" action="https://www.sogou.com/web" method="get">
    <input type="text" name="query">
    <input type="submit" value="提交" onclick="return MySubmit();">
</form>
*/

//form验证
function MySubmit() {
    var q = document.getElementsByName("query")[0];
    if(q.value.trim()){
        return true;
    }else{
        alert("请输入内容!!!");
        return false;
    }
}





// confirm事件
// 会出现弹窗 可以有确定/取消按钮 确定返回true 取消返回false
/*
<input type="button" value="上来呀" onmouseover="MyConfirm();">
*/

function MyConfirm() {
    var ret = confirm("xxxxxx");
    console.log(ret);
}






// 刷新页面
window.location.reload()
// 页面跳转
window.location.href = "http://www.baidu.com"




// 定时器
/*
<div id="haha" style="font-size: 20px; font-weight: bold; color: red">-欢迎xxxx莅临指导-</div>
<div>
    <input type="button" value="停止滚动" onclick="StopInterval();">
</div>
<div>
    <input type="button" value="停止弹窗" onclick="StopTimeout();">
</div>
*/

// setInterval setTimeout 第一个参数为操作函数 第二个参数为时间
// 这两个都是起一个线程进行事件的触发 时间单位是毫秒
// setInterval是每个设定的时间触发一次 可以通过clearInterval停止
// setTimeout是设定时间到达后执行一次 可以通过clearTimeout停止
var obj = setInterval("Func()", 500);
var objj = setTimeout("alert()", 5000);
function StopTimeout() {
    clearTimeout(objj);
}
function StopInterval() {
    clearInterval(obj);
}
function Func() {
    var nid = document.getElementById("haha");
    var text = nid.innerText;
    var firstText = text.charAt(0);
    var subText = text.substring(1,text.length);
    nid.innerText = subText + firstText;
}









/*
<div id="n1">
    111
    <div class="c2">
        222
        <a href="http://www.baidu.com">
            baidu
        </a>
    </div>
</div>
<div id="n2">222</div>
<div id="n3" class="c1">333</div>
<input type="text" checked="checked" name="haha">
*/

// 基本选择器
// $即jquery
$("div").text("XXXX");          // 标签选择器
$("#n1").text("123");           // id选择器
$(".c1").text("Haha");          // class选择器
$(".c2,#n2,a").text("OK");      // 组合选择器
$("#n1 .c2 a").text("Baidu");   // 层级选择器

$("#n1 > .c2").text("@@@@");    // child 子标签
$("#n1 + div").text("@@@@");    // 紧挨标签
$("#n1 ~ div").text("@@@@");    // 兄弟标签



// 筛选器
$("div:first");             // 选中标签中的第一个
$("input:not(:checked)");   // 所有没有被选中的
$("tr:even");               // 所有索引值为偶数的 eg: index=0,2,4...
$("tr:odd");                // 所有索引值为奇数的 eg: index=1,3,5...
$("tr:eq(1)");              // 索引值为1
/*
value = 2
tmp = "tr:eq({0})".format(value)
$(tmp)
*/ 
$("tr").eq(1);
$("tr:focus");              // 获得焦点
$("div:contains('Sam')");   // 内容包含Sam
$("div:empty");             // 内容为空

/*
<div attribute="xxxx"></div>
*/
$("div[attribute='xxxx']");
$("div[attribute!='xxxx']");
$("div[attribute^='xxxx']");
$("div[attribute$='xxxx']");

$("ul li:first-child");

$(":input");
$(":input[type='password']");
$(":password");
$("input:checked");


$("tr").eq(1);
$("tr").first();
$("tr").last();
$("div").hasClass("c1");
$("span").children();       // 所有子标签
$("div").find("a");         // 子子孙孙中查找

$(".c1").next();        // 下一个
$("#n1").nextAll();     // 下面所有
$(".c2").prev();        // 上一个
$("#n2").prevAll();     // 上面所有
$("#n3").siblings();    // 所有兄弟标签
$(".c3").parent();      // 父标签
$("n4").parent().siblings();


this // 表示当前的标签




function Func(ths) {
    console.log($(ths).text());
    $(ths).next().removeClass("hide");
    $(ths).parent().siblings().find(".body").addClass("hide");
}

function ChangeTab(ths) {
    $(ths).addClass("current").siblings().removeClass("current");
    var contentID = $(ths).attr("flag");
    var tmp = "#" + contentID;
    $(tmp).removeClass("hide").siblings().addClass("hide");
}



//attr: 标签中所有属性都适用，出checkbox,radio
attr("name", "sam")
attr("id")
//prop: checkbox,radio
prop("checkbox",true)
prop("radio",false)


function SelectAll() {
    // $("table input[type='checkbox']")
    $("table input[type='checkbox']").prop("checked",true);
    console.log("select all");
}

function ClearAll() {
    $("table input[type='checkbox']").prop("checked",false);
    console.log("clear all");
}

// each用法: $("div").each(function(){})
function ReserveAll() {
    // each 每一个循环度执行这个function
    // $(this)表示当前标签
    $("table input[type='checkbox']").each(function () {
        var isChecked = $(this).prop("checked");
        if(isChecked){
            $(this).prop("checked",false);
        }else{
            $(this).prop("checked",true);
        }
    });
    console.log("Reserve all");
}





// each的另一种用法: $.each(xxx,function(xx,xx){})
// 如果是两个参数 可以获得index和值或者key和值
// 如果是一个参数 可以获得index或者key
var userList = [11,22,33,44];
$.each(userList,function (index,item) {
    console.log(index,item);
});

var dict = {"key1":"value1", "key2":"value2"};
$.each(dict,function (key,value) {
    console.log(key,value);
});






// 添加删除class属性
// 如果标签没有该class属性 添加
// 如果标签有该class属性 移除
/*
<div id="NID">DIV</div>
*/

$("#NID").toggleClass("hide");





// 获得及设定标签中的文本内容
$("nid").text();
$("nid").text("shedingdezhi");
// 获得及设定标签中的HTML内容
$("nid").html();
$("nid").html("shedingdezhi");
// 获得及设定select textarea input系列的内容
$("input[type='text']").var();
$("input[type='text']").var("shedingdezhi");






// css操作标签style中的设定
$("#nid").css("color","red");





/*
<style>
    .go-top{
        position: fixed;
        bottom: 0;
        right: 0;
        width: 100px;
        height: 100px;
    }
    .hide{
        display: none;
    }
</style>
<div style="height: 2000px;background-color: #dddddd;">
    <div id="content" style="height: 200px; background-color: lightblue; overflow: auto">
        <p>Content</p>
        <p>Content</p>
        <p>Content</p>
        <p>Content</p>
        <p>Content</p>
        <p>Content</p>
        <p>Content</p>
        <p>Content</p>
    </div>
    <div>
        <a href="" onclick="smallGoTop();">小窗返回顶部</a>
    </div>
</div>
<div class="go-top hide">
    <a href="" onclick="GoTop();">返回顶部</a>
</div>

*/


// 返回顶部 scrollTop
// 返回左面 scorllLeft
function GoTop() {
    $(window).scrollTop(0);
}

function smallGoTop() {
    $("#content").scrollTop(0);
}
// 默认返回顶部不出现
window.onscroll = function () {
    var currentTop = $(window).scrollTop();
    if(currentTop>100){
        $(".go-top").removeClass("hide");
    }else{
        $(".go-top").addClass("hide");
    }
};




// offset
// 获取匹配元素在当前视口的相对偏移
//返回的对象包含两个整型属性：top 和 left，以像素计。此方法只对可见元素有效。
$("#nid").offset({top:xxx,left:xxx});
var offS = $("#nid").offset();
var left = offS.left;
var top = offS.top;




// position
// 获取匹配元素相对父元素的偏移
// 返回的对象包含两个整型属性：top 和 left。为精确计算结果，请在补白、边框和填充属性上使用像素单位。此方法只对可见元素有效
var pos = $("#nid").position();
var left = pos.left;
var top = pos.top;


// scrollTop
// 获取匹配元素相对滚动条顶部的偏移
// 此方法对可见和隐藏元素均有效
var p = $("p:first");
$("p:last").text( "scrollTop:" + p.scrollTop() );


$("div.demo").scrollTop(300);


// scrollLeft
//获取匹配元素相对滚动条左侧的偏移
// 此方法对可见和隐藏元素均有效
var p = $("p:first");
$("p:last").text( "scrollLeft:" + p.scrollLeft() );


$("div.demo").scrollLeft(300);


// height
// 取得匹配元素当前计算的高度值（px）
// 在 jQuery 1.2 以后可以用来获取 window 和 document 的高
$("p").height();
$("p").height(20);


// width
// 取得第一个匹配元素当前计算的宽度值（px）
// 在 jQuery 1.2 以后可以用来获取 window 和 document 的宽
$("p").width();
$("p").width(20);


// 滑轮滚动的高度 + window的高度 = 文档的高度 说明滑轮到底
window.onscroll = function () {
    if($(window).height()+$(window).scrollTop() == $(document).height()){
        console.log("bottom");
    }else{
        console.log("continue");
    }
};



// append/appendTo

// prepend/prependTo



// empty() 清空标签内容
$("#nid").empty();
// remove() 删除标签
$("#nid").remove();
// detach() 删除标签 返回被删除的标签
var ret = $("#nid").detach();
$("container").append(ret);




// clone
$("b").clone().prependTo("p");

// clone出的标签也有相同的功能
$("button").click(function(){
  $(this).clone(true).insertAfter(this);
});




// 最基本的jQuery绑定事件
$("li").click(function () {
    var temp = $(this).text();
    alert(temp);
})
or
$("li").bind("click",function(){
    var temp = $(this).text();
    alert(temp);
})


// unbind
$("li:last").unbind("click");

/*
blur([[data],fn])
change([[data],fn])
click([[data],fn])
dblclick([[data],fn])
error([[data],fn])1.8-
focus([[data],fn])
focusin([data],fn)
focusout([data],fn)
keydown([[data],fn])
keypress([[data],fn])
keyup([[data],fn])
mousedown([[data],fn])
mouseenter([[data],fn])
mouseleave([[data],fn])
mousemove([[data],fn])
mouseout([[data],fn])
mouseover([[data],fn])
mouseup([[data],fn])
resize([[data],fn])
scroll([[data],fn])
select([[data],fn])
submit([[data],fn])
*/


// click 一开始绑定 后来新添的标签不会有效果
// delegate 不是一开始绑定 而是调用的时候才绑定 再执行
$("ul").delegate("li","click",function () {
    var temp = $(this).text();
    alert(temp);
})

$("ul").undelegate("li","click");





// 当前文档准备就绪
// 优化页面加载问题 例如图片还未加载 文档结构加载完成就需要执行的js
// 将javascript代码放于该函数中
$(document).ready(function(){});
or
$(function(){});



// 鼠标拖动窗口
// 链式编程
$("#title").mouseover(function () {
    $(this).css("cursor","move");
}).mousedown(function (e) {
    var _event = e || window.event;
    var ord_x = _event.clientX;
    var ord_y = _event.clientY;

    var parent_left = $(this).parent().offset().left;
    var parent_top = $(this).parent().offset().top;

    $(this).bind("mousemove", function (e) {
        var _new_event = e || window.event;
        var _new_x = _new_event.clientX;
        var _new_y = _new_event.clientY;

        var _left = parent_left + (_new_x - ord_x);
        var _top = parent_top + (_new_y - ord_y);
        $(this).parent().offset({top:_top,left:_left});
    })
}).mouseup(function () {
    $(this).unbind("mousemove");
});








// AJAX请求
/*
<input type="text" id="n1" name="pp">
<input type="button" value="提交" onclick="Submit();">
*/

function Submit() {
    var inp = $("#n1").val();
    var inpName = $("#n1").attr("name");
    $.ajax({
        url:"http://127.0.0.1:8000/index",
        data: {"inp": inp, "inpName": inpName},
        type: "POST",
        success: function (arg) {
            // 当请求执行完成后 自动调用
            // arg 服务器返回的数据
        },
        error: function () {
            // 当请求执行错误后 自动调用
        }
    });
}

// AJAX 本域: 请求直接返回

// AJAX 跨域: jsonp
/*
客户端
    发送格式    jsonp
    函数名
服务端
    函数名(返回的数据)
*/

$.ajax({
    url:"http://xxxxxxx",
    data: {},
    type: "GET",
    dataType: "jsonp",
    jsonp: "callback",
    jsonpCallback: "list",
    // {"callback": "list"}
    success: function (arg) {
        // 当请求执行完成后 自动调用
        // arg 服务器返回的数据
        var jsonpArray = arg.data;
        $.each(jsonpArray, function (key,value) {
            var week = value.week;
            var temp = "<h1>" + week + "</h1>";
            $("#container").append(temp);
            var listArray = value.list;
            $.each(listArray, function (k,v) {
                var link = v.link;
                var name = v.name;
                var strings = "<a href=" + link + ">" + name + "</a><br/>";
                $("#container").append(strings);
            })
        })
    },
    error: function () {
        // 当请求执行错误后 自动调用
    }
});

// $.get
// $.post





// 扩展方法 先扩展后使用

// extend.js 自执行函数
(function (arg) {
    // 不包含选择器
    arg.extend({
        Sam: function() {
            return "Liuming";
        },
        Sugar: function () {
            return "Liushuge";
        },
    });
    // 包含选择器
    arg.fn.extend({
        Jack: function () {
            return "Jack";
        },
        Rose: function () {
            return "Rose";
        }
    });
})(jQuery);

// <script src="jquery-3.3.1.js"></script>
// <script src="extend.js"></script>
// 先引用jQuery 再引用自建js
alert($.Sam());
alert($.Sugar());
alert($("#nid").Jack());
alert($("#id").Rose());






































STATUS = [
    {"id":"0", "value":"上线"},
    {"id":"1", "value":"下线"},
    {"id":"2", "value":"未知"}
];



<table border="1">
    <thead>
        <tr>
            <th>选择</th>
            <th>主机名</th>
            <th>端口</th>
            <th>状态</th>
        </tr>
    </thead>
    <tbody id="tbl">
        <tr>
            <td><input type="checkbox"></td>
            <td edit="true">Server01</td>
            <td>8888</td>
            <td edit="true" edit-type="select" sel-val="1" global-key="STATUS">在线</td>
        </tr>
        <tr>
            <td><input type="checkbox"></td>
            <td edit="true">Server02</td>
            <td>77</td>
            <td edit="true" edit-type="select" sel-val="2" global-key="STATUS">下线</td>
        </tr>
        <tr>
            <td><input type="checkbox"></td>
            <td edit="true">Server03</td>
            <td>555</td>
            <td edit="true" edit-type="select" sel-val="1" global-key="STATUS">在线</td>
        </tr>
    </tbody>
</table>










