/**
 * 名前空間を作成します。
 * 既に存在している階層については作成しません。
 * @prame ns .区切りの名前空間文字列
 * 依存関係については、requiere.jsでの管理やgulpのpolify等は行いません。
 * また、オブジェクトの階層によって、ライブラリを管理し必要に応じて即時関数を利用しグローバル領域を安全に保ってください。
 */
namespace = function(ns) {
    var o=null;
	var unit=ns.split(".");
    o=window;
	for (var j=0; j<unit.length; j=j+1) {
            o[unit[j]]=o[unit[j]] || {};
            o=o[unit[j]];
	}
    return o;
};

namespace("axio.authEmpCodeList");

$(function() {
	var isPosting = false;

	// ヘッダチェックボックスchange処理
	$("#checkAll").on("change", function(event) {
//		alert("checkAll change");
		event.preventDefault();

		var checked = $("#checkAll").prop("checked");
		var cnt = $("#searchResultCount").val();
		if (isNaN(cnt)) cnt = 0;
		for (var i = 0; i < cnt; i++) {
			$("#employmentCodeCheck_" + i).prop("checked", checked);
		}
	});

	// 検索ボタンclick処理
	$("#Search").on("click", function(event) {
//		alert("Search click");
		if (isPosting) return false;
		isPosting = true;
		event.preventDefault();

		var cnt = $("#searchResultCount").val();
		var vals = [];
		if (isNaN(cnt)) cnt = 0;
		for (var i = 0; i < cnt; i++) {
			if ($("#employmentCodeCheck_" + i).prop("checked")) {
				vals.push({"employmentCode":"" + $("#employmentCodeCheck_" + i).val()});
			}
		}
		$("#checkedCodes").val(JSON.stringify(vals));

		$.ajax({
			url: $(this).data("action"),
			type: "POST",
			data: $(this).parents("form").serialize(),
			success: function(result){
//				alert("通信成功");
				$("#modal_dailog_body").empty();
  				$("#modal_dailog_body").html(result);
    		},
			error: function(err) {
//				alert("通信エラー");
				console.log(err);
				isPosting = false;
				return false;
			}
		});
	});

	// 確定ボタンclick処理
	$("#Ok").on("click", function(event) {
//		alert("Ok click");
		event.preventDefault();

		var cnt = $("#searchResultCount").val();
		var vals = [];
		if (isNaN(cnt)) cnt = 0;
		for (var i = 0; i < cnt; i++) {
			if ($("#employmentCodeCheck_" + i).prop("checked")) {
				vals.push({"employment":"" + $("#employmentCodeCheck_" + i).val(), "name":"" + $("#employmentNameHidden_" + i).val()});
			}
		}
		vals = vals.sort(function(val1, val2) {
			return (val1.employment > val2.employment ? 1 : -1);
		});

		axio.authRuleSet.dailogCallback(JSON.stringify(vals),null);
	});
});
