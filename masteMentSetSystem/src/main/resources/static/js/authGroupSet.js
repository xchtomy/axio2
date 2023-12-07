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

namespace('axio.authGroupSet');

/**
 * ダイヤログコールバック
 */
axio.authGroupSet.dailogCallback = function dailogCallback (res, err) {
	document.getElementById("ActionErrorMessage").style.display="none";
	var cfrom = $('#callFrom').val();
	//alert('dailog ' + cfrom + ' return <br /> res:' + res + ' <br /> err:' + err);

	if (cfrom == 'groupRegistSearch') {
		$('#changedFlg').val('');
		$('#editFlg').val('');
	}

	if (err) {
		$('#ActionErrorText').val(err);
		$('#ActionErrorMessage').show();
	} else {
		//console.log(res);
		const obj = res ? JSON.parse(res) : null;
		if (obj && obj.length > 0) {
			$('#groupId').val(obj[0].groupId);
			$('#groupNameEn').val(obj[0].groupNameEn);
			$('#groupNameJp').val(obj[0].groupNameJp);
			$('#groupStartDate').val(obj[0].startDate);
			$('#groupEndDate').val(obj[0].endDate);
			$('#groupDetail').val(obj[0].note);
		} else {
			$('#groupId').val('');
			$('#groupNameEn').val('');
			$('#groupNameJp').val('');
			$('#groupStartDate').val('');
			$('#groupEndDate').val('');
			$('#groupDetail').val('');
		}
		$('#reflectFunction').val(cfrom);
		$('#paramVal').val(res);
		$('#authGroupSetForm').attr('action','./authGroupSet');
		$('#authGroupSetForm').submit();
	}
}


$(function() {
	var isPosting = false;

	/**
	 * テキストボックスの値が（input type=text）　変更ある場合
	 */
	$('input[type="text"]').change(function(e) {
		document.getElementById("ActionErrorMessage").style.display="none";
		$("#changedFlg").val('1');
	});


	/**
	 * グループ検索ボタン押下
	 */
	$('#groupSearch').on('click', function(e){
	  //alert("click [groupRegistSearch]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//変更ある場合、確認メッセージ表示
		var m = "変更内容が登録されていません。<br />保存を行わない場合、変更内容は破棄されます。<br />よろしいですか？";
		if ($("#changedFlg").val() == '1' || $("#editFlg").val() == '1') {
			authGroupSetConfirm( e, m,
					// 確定ボタン押下の場合、グループ検索モーダル画面呼び出す
					function(){
						setTimeout(function(){searchGroupData();},0);
				   });
		}else{
			// グループ検索モーダル画面呼び出す
			setTimeout(function(){searchGroupData();},0);
		}
		//ボタン押下開放
		isPosting = false;
    });


	/**
	 * グループ検索モーダル画面呼び出す
	 */
	function searchGroupData() {
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		$('#callFrom').val('groupRegistSearch');
		$('#callParameter').val("");
		$('#callReturn').val("");

//		var groupid = $('#groupId').val();
//		var arr = [];
//
//		if (groupid) {
//			var p = {};
//			p['groupId'] = groupid;
//			arr.push(p);
//			$('#callParameter').val(JSON.stringify(arr));
//		} else {
//			$('#callParameter').val("");
//		}

		$.ajax({
			url: "./authGroupList",
    		type: "POST",
    		data: $('#dialogParamForm').serialize(),
    		success: function(result){
    				$("#modal_dailog_body").html(result);
    				$("#listModal").modal('show');
    				//ボタン押下開放
    				isPosting = false;
    		},
			error: function(err) {
				console.log(err);
				//ボタン押下開放
				isPosting = false;
			}
		});
	}

	/**
	 * グループ保存ボタン押下
	 */
	$("#groupUpdate").click(function(e){
		//alert("click [groupUpdate]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		var m = "<p> 画面上のグループ情報を保存します。<br />よろしいですか？</p>";
		authGroupSetConfirm( e, m,
			function(){
				$('#authGroupSetForm').attr('action','./authGroupSetSave');
		        $('#authGroupSetForm').submit();
		});

		//ボタン押下開放
		isPosting = false;
	});

	/**
	 * グループ削除ボタン押下
	 */
	$("#groupDelete").click(function(e){
		//alert("click [groupDelete]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		var m = "<p> 画面上のグループ情報を削除します。<br />よろしいですか？</p>";
		authGroupSetConfirm( e, m,
			function(){
				$('#authGroupSetForm').attr('action','./authGroupSetDelete');
				$('#authGroupSetForm').submit();
		});

		//ボタン押下開放
		isPosting = false;
	});


	/**
	 * クリアボタン押下
	 */
	$("#groupClear").click(function(e){
		//alert("click [groupClear]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		var m = "画面上のグループ情報をクリアします、よろしいですか？<br />（変更内容が破棄されます）";
		if ($("#changedFlg").val() == '1' || $("#editFlg").val() == '1') {
			authGroupSetConfirm( e, m,
					// 確定ボタン押下の場合、初期化処理する
					function(){
						$('#authGroupSetForm').attr('action','./authGroupSetClear');
						$('#authGroupSetForm').submit();
				   });
		}else{
			//初期化処理する
			$('#authGroupSetForm').attr('action','./authGroupSetClear');
			$('#authGroupSetForm').submit();
		}
		//ボタン押下開放
		isPosting = false;
	});

    /**
     * ボタン押下時確認ダイヤログメッセージ
     */
	function authGroupSetConfirm(e,message,okcallback,ngcallback) {
		var that = this;
		var confirmText = "変更内容が登録されていません。<br />保存を行わない場合、変更内容は破棄されます。<br />よろしいですか？"
		if (message) {
			confirmText = message;
		}
		var $div = $("<div id='_dialogLeave'><span>" + confirmText + "</span></div>");
		e.preventDefault();
		$div.dialog({
			title: '確認',
			modal:true,
			autoOpen: false,
			modal: true,
			buttons: [
				{
					text: 'OK' ,
					class: 'btn'  ,
					click: function(){
		                preventEvent = false;
						$(this).dialog("close");
						if(okcallback) {
							okcallback();
						}
					}
				},
				{
					text: 'キャンセル' ,
					class: 'btn' ,
					click: function(){
						if(ngcallback) {
							ngcallback();
						}
						$(this).dialog("close");
					}
				}
			],
			open:function(event, ui){ $(".ui-dialog-titlebar-close").hide();}
		});
		$div.dialog('open');
	};


	/**
	 * ログアウトボタン押下
	 */
	$("#btn_logout").on("click", function(e) {
		var m = "変更が保存されていないため、変更した内容が破棄されますが宜しいでしょうか？";
		var that = this;
		if ($("#changedFlg").val() == '1' || $("#editFlg").val() == '1') {
			authGroupSetConfirm(e, m,
				function(){
					$("#changedFlg").val('');
					$("#editFlg").val('');
					window.location.href = $(that).attr("href");
					console.log("href:" + window.location.href);
			});
		}
	});

});
