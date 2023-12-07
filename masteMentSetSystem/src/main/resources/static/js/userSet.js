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

namespace('axio.userSet');

$(function() {
	var isPosting = false;

	/*
	 * モダール画面終了後のイベント登録(呼び出し元画面回復処理）
	 */
	$('#listModal').on('hidden.bs.modal', function (event) {
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

	//エラーメッセージダイアログの表示
	if($("#errMessage").val() != ''){
		$("#axioErrDialog").dialog({
			modal:true,
			buttons:[
				{
					text: 'OK' ,
					class: 'btn' ,
					click: function(){
						$(this).dialog("close");
					}
				}
			],
			open:function(event, ui){
				$(".ui-dialog-titlebar-close").hide();
			},
			close:function(event, ui){
				$('#axioErrDialog').remove();
			}
		});
	}

    // ダイヤログコールバック
	axio.userSet.dailogCallback = function dailogCallback (res, err) {
		var cfrom = $('#callFrom').val();

		//コード選択ダイヤログ画面から戻した場合
		$('#editFlg').val('1');

		if (err) {
			$('#ActionErrorText').val(err);
			$('#ActionErrorMessage').show();
		} else {
			const obj = res ? JSON.parse(res) : null;
			parseOrganizationRetVal(obj);
		}
	}

	/**
	 * 組織コードテキスト欄をフラッシュ
	 */
	parseOrganizationRetVal = function(o) {
		var v = '';
		if (o) {
			//一覧画面からの戻り値をセット
			for (var i=0; i<o.length; i++) {
				// テキストエリアに値をセット
				var t1 = o[i].organization + ':' + o[i].name;
				var t2 = o[i].organization;
				var t3 = o[i].name;

				$('#organization').val(t1);
				// テキストエリアに値をセット
				$('#orgCode').val(t2);
				// テキストエリアに値をセット
				$('#orgName').val(t3);

			}
		}
	}

	/**
	 * 組織コード選択ボタン押下（open modal）
	 */
	$('#organizationSelect').on('click', function(e){
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//組織選択モーダル画面呼び出す
		$('#callFrom').val('organizationSelect2');
		$('#callParameter').val(splitToJsonStr('organization'));
		$('#callReturn').val("");
		$.ajax({
			url: "./authOrgCodeList",
			type: "POST",
			data: $('#dialogParamForm').serialize(),
			success: function(result){
				$("#modal_dailog_body").html(result);
	    		$("#listModal").modal('show');
	    		//ボタン押下開放
	    		isPosting = false;
			},
	        error: function(err){
				//ボタン押下開放
				isPosting = false;
	        }
		});
	});

	/**
	 * 保存ボタン押下
	 */
	$('#saveBtn').click(function(e) {
		//alert("click [dailogGroupSearch]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		var m = "<p>利用者情報が保存されます。<br />よろしいですか？</p>";

		userSetConfirm( e, m,
				function(){
				//検索処理
				$.ajax({
					url: "./userSetSave",
					type: "POST",
					data: $("#UserSetForm").serialize(),
					success: function(result){
						$('body').html(result);
						//ボタン押下開放
						isPosting = false;
					},
					error: function(err) {
						//ボタン押下開放
						isPosting = false;
					}
				});
			});

		//ボタン押下開放
		isPosting = false;
	});

	/**
	 * CSVダウンロードボタン押下
	 */
	$('#downloadBtn').click(function(e) {
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;

		isPosting = true;

		if($("#changedFlg").val() == 'ON'){
			var title = "確認";
			var m = "変更があります。<br/>利用者情報を保存してください。";

			showAlert(title,m);

		}else{
			var m = "<p>利用者情報CSV出力を開始します。<br/>よろしいですか？</p>";

			userSetConfirm(e, m,
					function(){
						$('#UserSetForm').attr('action', './userSetCsvDownload');
						$('#UserSetForm').submit();
					});
		}

		isPosting = false;
	});

	/**
	 * ログアウトボタン押下
	 */
	$("#btn_back").on("click", function(e) {
		var m = "変更が保存されていないため、変更した内容が破棄されますが宜しいでしょうか？";
		var that = this;
		console.log($("#changedFlg").val());
		if ($("#changedFlg").val() == 'ON') {
			userSetConfirm(e, m,
				function(){
					$("#changedFlg").val('');
					$('#UserSetForm').attr('action', './userList');
					$('#UserSetForm').submit();
				});
		}
	});


});


/* 下記は呼び出す用fucntion */

/**
 * エリア表示／非表示切り替える
 * @param name
 * @returns
 */
function changeShow(name){
	var itemName = "#" + name;
	$(itemName).toggleClass("is-on");
	$(itemName).toggleClass("is-hide");
};

/**
 * タブ画面切り替える
 * @param name
 * @returns
 */
function showTab(name){
	// tabボタン表示変更
	var obj = event.target.id;
	$(".jsTabMenuItem").removeClass("is-on");
	$("#"+obj).addClass("is-on");

	// tabエリア表示変更
	$("#div_1").removeClass("is-on");
	$("#div_2").removeClass("is-on");
	$("#div_3").removeClass("is-on");
	$("#div_4").removeClass("is-on");

	$("#"+ name).addClass("is-on");

};

/**
 * 行追加
 * @returns
 */
function addRow(){
	// チェック
	if(!addRowCheck()){ return };

    // 行番
	var no = '<td style="width:40px;" class="no"></td>';
    // 会社コード
	var company = '<td style="width:120px;" ><input style="width: 90px; padding:0px;" type="text" value="' + $('#companyCode').val() + '" class="companyCode align-center" readonly></td>';
	// 部署コード
	var orgcode = '<td style="width:120px;" ><input style="width: 90px; padding:0px;" type="text" value="' + $('#orgCode').val() + '" class="align-center organizationCode" readonly></td>';
	vartmp = $('#orgName').val() +"";
    // 部署名
	var orgname = '<td style="width:460px;" ><input style="width: 430px; padding:0px; word-wrap:break-word; word-break:break-all;" type="text" value="' + $('#orgName').val() + '" class="align-left organizationNameJp" readonly></td>';
	// 役職
	var position = '<td style="width:100px;"><input type="hidden" value="' + $('#posselect option:selected').val() + '" class="positionCode" > <input type="text" style="width: 70px; padding:0px;" value="'+ $('#posselect option:selected').text() +'" class="align-center positionNameJp"  readonly></td>';
	// ボタン
	var delbutton = '<td style="width:120px;">'+ '<button type="button" style="width: 22px; padding:0px; background-color: #1F3990; border-color: #1F3990;border-radius: 0px; color:#FFFFFF;" onclick="delRow(this)">×</button>' +'</td>';

	var row = no + company + orgcode + orgname + position + delbutton;
	 $('#mantab').append('<tr>'+ row +'</tr>');

	resetRow();

	$('#changedFlg').val('ON');

	$('#organization').val("");
	// テキストエリアに値をセット
	$('#orgCode').val("");
	// テキストエリアに値をセット
	$('#orgName').val("");
	$('#posselect').val("");
}

/**
 * 行削除
 * @param obj
 * @returns
 */
function delRow(obj) {
	// 削除ボタンを押下された行を取得
	tr = obj.parentNode.parentNode;
	// trのインデックスを取得して行を削除する
	tr.parentNode.deleteRow(tr.sectionRowIndex);

	resetRow();

	$('#changedFlg').val('ON');
}

/**
 * 行nameリセット
 * @returns
 */
function resetRow() {
	$("#mantab td.no").each(function(i) {
		i = i + 1;
		$(this).text(i);
	});

	$('#mantab input.companyCode').each(function(i) {
		let name = 'userManCmbOrgInfoList['+ i +'].companyCode';
		$(this).attr('name' , name);
	});

	$('#mantab input.organizationCode').each(function(i) {
		let name = 'userManCmbOrgInfoList['+ i +'].organizationCode';
		$(this).attr('name' , name);
	});

	$('#mantab input.organizationNameJp').each(function(i) {
		let name = 'userManCmbOrgInfoList['+ i +'].organizationNameJp';
		$(this).attr('name' , name);
	});

	$('#mantab input.positionCode').each(function(i) {
		let name = 'userManCmbOrgInfoList['+ i +'].positionCode';
		$(this).attr('name' , name);
	});

	$('#mantab input.positionNameJp').each(function(i) {
		let name = 'userManCmbOrgInfoList['+ i +'].positionNameJp';
		$(this).attr('name' , name);
	});
}


/**
 * 行追加チェック
 * @returns
 */
function addRowCheck(){
	// 組織必須チェック
	if($('#organization').val() == null || $('#organization').val() == ""){
        var title ="チェックエラー"
		var message = "組織を検索してください";

		showAlert(title, message);
		return false;
	}

	// 役職必須チェック
	if($('#posselect option:selected').val() == ""){
        var title ="チェックエラー"
    	var message = "役職を検索してください";

    	showAlert(title, message);
    	return false;
	}

	// 発令兼務チェック
	var companyCode = $('#companyCode').val();
	var orgCode = $('#orgCode').val();

	var companyCodeList = $('#anntab td.companyCode');
	var organizationCodeList = $('#anntab td.organizationCode');

	for (var i=0; i<organizationCodeList.length; i++) {
		if( orgCode == organizationCodeList[i].innerText && companyCode == companyCodeList[i].innerText){

	        var title ="チェックエラー";
	    	var message = "対応兼務が既にあります。重複追加はできません。";
	    	showAlert(title, message);
	    	return false;
		}
	}

	// 手動兼務チェック
	var companyCodeList = $('#mantab td .companyCode');
	var organizationCodeList = $('#mantab td .organizationCode');

	for (var i=0; i<organizationCodeList.length; i++) {
		let companyCode_tmp= companyCodeList[i].value;
		let orgCode_tmp = organizationCodeList[i].value;

		if( orgCode == orgCode_tmp && companyCode == companyCode_tmp){
	        var title ="チェックエラー"
		    var message = "対応兼務が既にあります。重複追加はできません。";
		    showAlert(title, message);
		    return false;
		}
	}

	return true;
}


/**
 *  ダイヤログ画面
 * @param e
 * @param message
 * @param okcallback
 * @param ngcallback
 * @returns
 */
function userSetConfirm(e,message,okcallback,ngcallback) {
	var that = this;
    //既存のダイアログエリア削除
    $('#comfirmDialog').remove();
	var $div = $("<div id='comfirmDialog'><span>" + message + "</span></div>");

	if(e != null){
		e.preventDefault();
	}

	$div.dialog({
		title: '確認',
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
		open:function(event, ui){
			$(".ui-dialog-titlebar-close").hide();
		},
		close:function(event, ui){
			$('#comfirmDialog').remove();
		}
	});

	$div.dialog('open');
}


/**
 * alert画面
 * @param title
 * @param message
 * @returns
 */
function showAlert(title, message) {
    //既存のダイアログエリア削除
    $('#comfirmDialog').remove();
	var $div = $("<div id='comfirmDialog'><span>" + message + "</span></div>");

	$div.dialog({
		modal:true,
		autoOpen: false,
		modal: true,
		title: title,
		buttons: [
			{
				text: 'OK' ,
				class: 'btn'  ,
				click: function(){
	                preventEvent = false;
					$(this).dialog("close");
				}
			}
		],
		open:function(event, ui){
			$(".ui-dialog-titlebar-close").hide();
		},
		close:function(event, ui){
			$('#comfirmDialog').remove();
		}
	});

	$div.dialog('open');
}

/**
 * JSONオブジェクトの文字列作成
 * @param id
 * @param item1
 * @param item2
 * @param item3
 * @returns
 */
function splitToJsonStr(id, item1, item2, item3) {
	var s = $('#'+id).val().split(';');
	var r = [];
	$.each(s, function(ind, v) {
		if (v) {
			var c = v.split(':');
			var rs = {};
			if (item1) {
				rs[item1] = c[0];
			}
			if (item2) {
				rs[item2] = c[1];
			}
			if (item3) {
				rs[item3] = c[2];
			}
			r.push(rs);
		}
	});
	return JSON.stringify(r);
};
