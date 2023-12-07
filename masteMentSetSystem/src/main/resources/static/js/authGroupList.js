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

namespace('axio.authGroupList');

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
		$("#groupStartDate").removeClass('hasDatepicker');
		$("#groupEndDate").removeClass('hasDatepicker');
		$("#groupStartDate").datepicker({
				 showButtonPanel: false		// 「Today」「Done」ボタン 無効
				,changeMonth: false 		// 「月」リスト選択 無効
				,changeYear: false			// 「年」リスト選択 無効
				,dateFormat: "yy/mm/dd"		// 日付フォーマット yyyy/MM/dd
				,firstDay: 0 			 	// 週の最初の曜日 0:日曜日
				, beforeShow: function (elem,dp) {
	  	            dp.dpDiv.css('z-index', '10');
	  	        }
		});
		$("#groupEndDate").datepicker({
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

	/**
	 * グループ検索ボタン押下（open modal）
	 */
	$('#dailogGroupSearch').on('click', function(e){
		//alert("click [dailogGroupSearch]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//検索処理
		$.ajax({
    		url: "./authGroupListSearch",
    		type: "POST",
    		data: $('#authGroupListForm').serialize(),
    		success: function(result){
    			$("#modal_dailog_body").empty();
    			$("#modal_dailog_body").html(result);
    			//ボタン押下開放
    			isPosting = false;
    		},
			error: function(err) {
				console.log(err);
				//ボタン押下開放
				isPosting = false;
			}
		});
    });

	/**
	 * 確定ボタン押下（open modal）
	 */
	$('#dailogGroupOK').on('click', function(e){
		//通常のアクションをキャンセルする
		e.preventDefault();

		//選択されたレコードのIDを取得
		var groupId =  $('input[id^=listCheck]:checked').val();
		console.log('groupId='+groupId);

		if (!groupId) {
			if (cfrom == 'groupSelect') {
				// ルール設定画面から呼び出すの場合
				setTimeout(function(){axio.authRuleSet.dailogCallback(null,null);},0);
			} else {
				// グループ設定画面からの呼び出すの場合
				setTimeout(function(){axio.authGroupSet.dailogCallback(null,null);},0);
			}
			closeModalDailog();
		 } else {
			// 呼び出す元画面
			var cfrom = $('#dailogCallFrom').val();

			var cnt = $("#searchResultCount").val();
			var vals = [];
			if (isNaN(cnt)) cnt = 0;

			for (var i = 0; i < cnt; i++) {
				if ($("#listCheck_" + i).prop("checked")) {
					vals.push({"groupId":"" + $("#listCheck_" + i).val(), "groupNameEn":""
						+ $("#groupNameEnHidden_" + i).val(), "groupNameJp":""
							+ $("#groupNameJpHidden_" + i).val(), "startDate":""
								+ $("#startDateHidden_" + i).val(), "endDate":""
									+ $("#endDateHidden_" + i).val(), "note":""
										+ $("#noteHidden_" + i).val()});
				}
			}
			// グループIDでソート
			vals = vals.sort(function(val1, val2) {
				return (val1.groupId > val2.groupId ? 1 : -1);
			});

			if (cfrom == 'groupSelect') {
				// ルール設定画面から呼び出すの場合
				setTimeout(function(){axio.authRuleSet.dailogCallback(JSON.stringify(vals),null);},0);
			} else {
				// グループ設定画面からの呼び出すの場合
				setTimeout(function(){axio.authGroupSet.dailogCallback(JSON.stringify(vals),null);},0);
			}
			closeModalDailog();
		}
    });

	/**
	 * modal dailog close
	 */
	function closeModalDailog() {
//		$('#listModal').modal('hide');
//		$('div.modal-backdrop.in').remove();
//		$('body').removeClass('modal-open');
	}

	// 結果一覧ヘッダチェックボックスchange処理
	$("#groupListCheckAll").on("change", function(event) {
		event.preventDefault();

		var checked = $("#groupListCheckAll").prop("checked");
		var cnt = $("#searchResultCount").val();
		if (isNaN(cnt)) cnt = 0;
		for (var i = 0; i < cnt; i++) {
			$("#listCheck_" + i).prop("checked", checked);
		}
	});

	// 結果一覧チェックボックス選択：複数・単一選択の分岐処理
	$('input[id^=listCheck]').change(function(){
		var cfrom = $('#dailogCallFrom').val();
		if (cfrom == 'groupSelect') {
			// ルール設定画面から呼び出すの場合、複数選択できる
			if ($(this).prop('checked')){
	            var checkval = $('input[id^=listCheck]:checked').val();
	            $("#checkGroupId").val(checkval);
	        }
		} else {
			// グループ設定画面からの呼び出すの場合、単一選択
			if ($(this).prop('checked')){
	            // 一旦全てをクリアして再チェックする
	            $('input[id^=listCheck]').prop('checked', false);
	            $(this).prop('checked', true);
	            var checkval = $('input[id^=listCheck]:checked').val();
	            $("#checkGroupId").val(checkval);
	        } else {
	            $("#checkGroupId").val('');
	        }
		}

	});

    /**
     * ボタン押下時確認ダイヤログメッセージ
     */
	function authGroupListConfirm(e,message) {
		var that = this;
		var confirmText = ""
		if (message) {
			confirmText = message;
		} else {
			return;
		}
        //既存のダイアログエリア削除
		var defer = $.Deferred();
		var $div = $("<div id='comfirmDialog' style='display: block; z-index: 1065;' ><span>" + confirmText + "</span></div>");

		$div.dialog({
			title: '確認',
			modal:true,
			autoOpen: true,
		    position: {"my":"center", "at":"center", "of":"#modalAuthGroupList"},
			buttons: [
				{
					text: 'OK' ,
					class: 'btn'  ,
					click: function(){
						defer.resolve("yes");
						$('#comfirmDialog').dialog("close");
					}
				},
				{
					text: 'キャンセル' ,
					class: 'btn' ,
					click: function(){
						defer.resolve("no");
						$('#comfirmDialog').dialog("close");
					}
				}
			]
			, open:function(event, ui){
				$(".ui-dialog-titlebar-close").hide();
				$('#comfirmDialog').parent().css('z-index', '1065');
			}
			, close:function(event, ui){
				$('#comfirmDialog').dialog('destroy');
			}
		});
		return defer.promise();
	};
});
