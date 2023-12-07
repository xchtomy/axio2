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

namespace("axio.authOrgCodeList");

$(function() {
	var isPosting = false;

	/*
	 * モダール画面終了後のイベント登録(呼び出し元画面回復処理）
	 */
	$('#listModal').on('hidden.bs.modal', function (event) {
		console.log('modal closed');
		$("#ui-datepicker-div").remove();
		$("#startDate").removeClass('hasDatepicker');
		$("#endDate").removeClass('hasDatepicker');
		$("#startDate").datepicker({
				 showButtonPanel: false		// 「Today」「Done」ボタン 無効
				,changeMonth: false 		// 「月」リスト選択 無効
				,changeYear: false			// 「年」リスト選択 無効
				,dateFormat: "yy/mm/dd"		// 日付フォーマット yyyy/MM/dd
				,firstDay: 0 			 	// 週の最初の曜日 0:日曜日
				, beforeShow: function (elem,dp) {
	  	            dp.dpDiv.css('z-index', '10');
	  	        }
		});
		$("#endDate").datepicker({
				 showButtonPanel: false		// 「Today」「Done」ボタン 無効
				,changeMonth: false 		// 「月」リスト選択 無効
				,changeYear: false			// 「年」リスト選択 無効
				,dateFormat: "yy/mm/dd"		// 日付フォーマット yyyy/MM/dd
				,firstDay: 0 			 	// 週の最初の曜日 0:日曜日
				, beforeShow: function (elem,dp) {
	  	            dp.dpDiv.css('z-index', '10');
	  	        }
		});
	});

	// ヘッダチェックボックスchange処理
	$("#checkAll").on("change", function(event) {
//		alert("checkAll change");
		event.preventDefault();

		var checked = $("#checkAll").prop("checked");
		var cnt = $("#searchResultCount").val();
		if (isNaN(cnt)) cnt = 0;
		for (var i = 0; i < cnt; i++) {
			$("#positionCodeCheck_" + i).prop("checked", checked);
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
			if ($("#positionCodeCheck_" + i).prop("checked")) {
				var code =  $("#positionCodeCheck_" + i).val().split(":");
				vals.push({"companyCode":"" + code[0], "positionCode":"" + code[1]});
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
			if ($("#positionCodeCheck_" + i).prop("checked")) {
				var code =  $("#positionCodeCheck_" + i).val().split(":");
				vals.push({"company":"" + code[0],"position":"" + code[1],"name":"" + $("#positionNameHidden_" + i).val()});
			}
		}
		vals = vals.sort(function(val1, val2) {
			return (val1.company > val2.company || (val1.company == val2.company && val1.position > val2.position) ? 1 : -1);
		});

		axio.authRuleSet.dailogCallback(JSON.stringify(vals),null);
	});
});
