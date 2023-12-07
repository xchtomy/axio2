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
			$("#departmentCodeCheck_" + i).prop("checked", checked);
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
			if ($("#departmentCodeCheck_" + i).prop("checked")) {
				var code =  $("#departmentCodeCheck_" + i).val().split(":");
				vals.push({"companyCode":"" + code[0], "organizationCode":"" + code[1]});
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

		// 呼び出す元画面
		var cfrom = $('#dailogCallFrom').val();

		var cnt = $("#searchResultCount").val();
		var vals = [];
		if (isNaN(cnt)) cnt = 0;
		for (var i = 0; i < cnt; i++) {
			if ($("#departmentCodeCheck_" + i).prop("checked")) {
				var code =  $("#departmentCodeCheck_" + i).val().split(":");
				vals.push({"company":"" + code[0],"organization":"" + code[1],"name":"" + $("#departmentNameHidden_" + i).val()});
			}
		}
		vals = vals.sort(function(val1, val2) {
			return (val1.company > val2.company || (val1.company == val2.company && val1.organization > val2.organization) ? 1 : -1);
		});

		if (cfrom == 'organizationSelect') {
			// ルール設定画面から呼び出すの場合
			axio.authRuleSet.dailogCallback(JSON.stringify(vals),null);
		} else if (cfrom == 'companySearch') {
			// セキュリティグループ登録画面からの呼び出すの場合
			axio.securityGrpSet.dailogCallback(JSON.stringify(vals),null);
		} else {
			// 利用者情報画面からの呼び出すの場合
			axio.userSet.dailogCallback(JSON.stringify(vals),null);
		}

	});

	// 結果一覧チェックボックス選択：複数・単一選択の分岐処理
	$('input[id^=departmentCodeCheck]').change(function(){
		var cfrom = $('#dailogCallFrom').val();
		if (cfrom == 'organizationSelect') {
			// ルール設定画面から呼び出すの場合、複数選択できる
			if ($(this).prop('checked')){
	            var checkval = $('input[id^=departmentCodeCheck]:checked').val();
	            //$("#checkGroupId").val(checkval);
	        }
		} else {
			// その他（セキュリティグループ登録、利用者情報）画面からの呼び出すの場合、単一選択
			if ($(this).prop('checked')){
	            // 一旦全てをクリアして再チェックする
	            $('input[id^=departmentCodeCheck]').prop('checked', false);
	            $(this).prop('checked', true);
	            var checkval = $('input[id^=departmentCodeCheck]:checked').val();
	            //$("#checkGroupId").val(checkval);
	        } else {
	            //$("#checkGroupId").val('');
	        }
		}

	});

});
