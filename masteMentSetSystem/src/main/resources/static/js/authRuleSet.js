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

namespace('axio.authRuleSet');

document.addEventListener('DOMContentLoaded', function() {
	console.log('DOM読み込み完了');

	// 背景色調整
	if ($('#userCode').val() == '') {
		document.getElementById('userCode').style.backgroundColor = '#eee';
	} else {
		document.getElementById('userCode').style.backgroundColor = '#66FFFF';
	}

	// 背景色調整
	if ($('#userExtCode').val() == '') {
		document.getElementById('userExtCode').style.backgroundColor = '#eee';
	} else {
		document.getElementById('userExtCode').style.backgroundColor = '#66FFFF';
	}

}, false);


/**
 * ダイヤログコールバック
 */
axio.authRuleSet.dailogCallback = function dailogCallback (res, err) {
	document.getElementById("ActionErrorMessage").style.display="none";
	var cfrom = $('#callFrom').val();
	//alert('dailog ' + cfrom + ' return <br /> res:' + res + ' <br /> err:' + err);

	if (cfrom == 'groupSelect') {
		$('#changedFlg').val('1');
	}
	else if (cfrom == 'ruleSearch'){
		$('#changedFlg').val('');
		$('#editFlg').val('');
	}
	else if (cfrom == 'userSelect') {
		$('#changedFlg').val('1');
		$('#editFlg').val('');
	}
	else if (cfrom == 'userExtSelect') {
		$('#changedFlg').val('1');
		$('#editFlg').val('');
	}
	else {
		//コード選択ダイヤログ画面から戻した場合
		$('#editFlg').val('1');
	}

	if (err) {
		$('#ActionErrorText').val(err);
		$('#ActionErrorMessage').show();
	} else {
		//console.log(res);
		const obj = res ? JSON.parse(res) : null;
		if (cfrom == 'ruleSearch')  {
			if (res) {
				$('#reflectFunction').val(cfrom);
				$('#paramVal').val(res);
			} else {
				$('#reflectFunction').val('');
				$('#paramVal').val('');
			}
			$('#authRuleSetForm').attr('action','./authRuleSet');
			$('#authRuleSetForm').submit();
		}
		else if (cfrom == 'groupSelect') {
			//サーバー送信しない、DOM更新
			parseGroupRetVal(obj);
//			//サーバー送信して、ページを再表示
//			$('#reflectFunction').val(cfrom);
//			$('#paramVal').val(res);
//			$('#authRuleSetForm').attr('action','./authRuleSet');
//			$('#authRuleSetForm').submit();
		}
		else if (cfrom == 'companySelect') {
			parseCompanyRetVal(obj);
		}
		else if (cfrom == 'employmentKbnSelect') {
			parseEmployRetVal(obj);
		}
		else if (cfrom == 'organizationSelect') {
			parseOrganizationRetVal(obj);
		}
		else if (cfrom == 'positionSelect') {
			parsePositionRetVal(obj);
		}
		else if (cfrom == 'userSelect') {
			parseUserRetVal(obj);
		}
		else if (cfrom == 'userExtSelect') {
			parseUserExtRetVal(obj);
		}
	}
}

/**
 * 紐付け済グループ一覧フラッシュ
 */
parseGroupRetVal = function (o) {

	var rows = '';
	if (o) {
		//tbodyのすべての行要素をクリア
		$('#ruleGroupList').empty();
		//tbodyの新しい行要素を追加
		for (var i=0; i<o.length; i++) {
		 rows = "<tr><td  id='ruleGroup_" + i + "' class='asm_data_table_header text-center'>グループ" + i+1 + ""
			+ "<input type='hidden' id='hgruleId_" + i + "' value='" + "" +"' name='ruleGroupList[" + i +"].ruleId'/></td>"
			+ "<td class='master-back-grey text-left' id='groupId_" + i +"' style='background-color: #66FFFF;'>"+ o[i].groupId + ""
			+ "<input type='hidden' id='hgroupId_" + i + "' value='" + o[i].groupId + "' name='ruleGroupList["+ i + "].groupId'/>"
			+ "<input type='hidden' id='hdelFlg_" + i + "'  value='false' name='ruleGroupList[" + i + "].delFlg'/></td>"
			+ "<td class='master-back-grey text-left' id='groupNameJP_" + i + "' style='background-color: #66FFFF;' >" + o[i].groupNameJp + ""
			+ "<input type='hidden' id='hgroupNameJP_" + i + "' value='" + o[i].groupNameJp + "' name='ruleGroupList[" + i + "].groupNameJP'/>"
			+ "<input type='hidden' id='hgroupNameEn_" + i + "' value='" + o[i].groupNameEn + "' name='ruleGroupList[" + i + "].groupNameEn'/></td>"
			+ "<td class='master-back-grey text-left' id='term_" + i + "' style='background-color: #66FFFF;' >" + o[i].startDate + "-" + o[i].endDate + ""
			+ "<input type='hidden' id='hstartDate_" + i + "'  value='" + o[i].startDate + "' name='ruleGroupList[" + i + "].startDate'/>"
			+ "<input type='hidden' id='hendDate_" + i + "' value='" + o[i].endDate + "' name='ruleGroupList[" + i + "].endDate'/></td>"
			+ "</tr>";

		 $('#ruleGroupList').append(rows);
		}
	} else {
		$('#ruleGroupList').empty();
	}
}

/**
 * 会社コードテキスト欄をフラッシュ
 */
parseCompanyRetVal = function (o) {

	var v = '';
	if (o) {
		//一覧画面からの戻り値をセット
		for (var i=0; i<o.length; i++) {
			v = v + o[i].company + ':' + o[i].name;
			if (i<o.length-1) {
				v = v + ';';
			}
		}
	}
	//テキストエリアに値をセット
	$('#companyCode').val(v);

}

/**
 * 雇用区分コードテキスト欄をフラッシュ
 */
parseEmployRetVal = function (o) {

	var v = '';
	if (o) {
		//一覧画面からの戻り値をセット
		for (var i=0; i<o.length; i++) {
			v = v + o[i].employment + ':' + o[i].name;
			if (i<o.length-1) {
				v = v + ';';
			}
		}
	}
	//テキストエリアに値をセット
	$('#employmentCode').val(v);
}

/**
 * 組織コードテキスト欄をフラッシュ
 */
parseOrganizationRetVal = function (o) {

	var v = '';
	if (o) {
		//一覧画面からの戻り値をセット
		for (var i=0; i<o.length; i++) {
			v = v + o[i].company + ':' + o[i].organization + ':' + o[i].name;
			if (i<o.length-1) {
				v = v + ';';
			}
		}
	}
	//テキストエリアに値をセット
	$('#organizationCode').val(v);
}

/**
 * 役職コードテキスト欄をフラッシュ
 */
parsePositionRetVal = function (o) {

	var v = '';
	if (o) {
		//一覧画面からの戻り値をセット
		for (var i=0; i<o.length; i++) {
			v = v + o[i].company + ':' + o[i].position + ':' + o[i].name;
			if (i<o.length-1) {
				v = v + ';';
			}
		}
	}
	//テキストエリアに値をセット
	$('#positionCode').val(v);
}

/**
 * ユーザーIDテキスト欄をフラッシュ（付与）
 */
parseUserRetVal = function (o) {

	var v = '';
	if (o) {
		//一覧画面からの戻り値をセット
		for (var i=0; i<o.length; i++) {
			v = v + o[i].user + ':' + o[i].name;
			if (i<o.length-1) {
				v = v + ';';
			}
		}

		if (o.length > 0) {
			// 背景色変更
			document.getElementById('userCode').style.backgroundColor = '#66FFFF';
		} else {
			// 背景色変更
			document.getElementById('userCode').style.backgroundColor = '#eee';
		}
	}

	//テキストエリアに値をセット
	$('#userCode').val(v);
}


/**
 * ユーザーIDテキスト欄をフラッシュ（除外）
 */
parseUserExtRetVal = function (o) {

	var v = '';
	if (o) {
		//一覧画面からの戻り値をセット
		for (var i=0; i<o.length; i++) {
			v = v + o[i].user + ':' + o[i].name;
			if (i<o.length-1) {
				v = v + ';';
			}
		}

		if (o.length > 0) {
			// 背景色変更
			document.getElementById('userExtCode').style.backgroundColor = '#66FFFF';
		} else {
			// 背景色変更
			document.getElementById('userExtCode').style.backgroundColor = '#eee';
		}
	}

	//テキストエリアに値をセット
	$('#userExtCode').val(v);
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
	 * ルール検索ボタン押下（open modal）
	 */
	$('#ruleSearch').on('click', function(e){
		//alert("click [ruleSearch]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//変更ある場合、確認メッセージ表示
		var m = "変更内容が登録されていません。<br />保存を行わない場合、変更内容は破棄されます。<br />よろしいですか？";
		if ($("#changedFlg").val() == '1' || $("#editFlg").val() == '1') {
			authRuleSetConfirm( e, m,
					// 確定ボタン押下の場合、ルール検索モーダル画面呼び出す
					function(){
						setTimeout(function() {searchRuleData();}, 0);
				   });
		}else{
			//ルール検索モーダル画面呼び出す
			setTimeout(function() {searchRuleData();},0);
		}
		//ボタン押下開放
		isPosting = false;
    });

	/**
	 * ルール検索モーダル画面呼び出す
	 */
	function searchRuleData() {
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		$('#callFrom').val('ruleSearch');
		$('#callParameter').val("");
		$('#callReturn').val("");

//		var ruleid = $('#ruleId').val();
//		var rulename = $('#ruleName').val();
//		var rulenote = $('#ruleNote').val();
//		var startdate = $('#startDate').val();
//		var enddate = $('#endDate').val();
//		var arr = [];
//
//		if (ruleid) {
//			var p = {};
//			p['ruleId'] = ruleid;
//			p['ruleName'] = rulename;
//			p['ruleNote'] = rulenote;
//			p['startDate'] = startdate;
//			p['endDate'] = enddate;
//			arr.push(p);
//			$('#callParameter').val(JSON.stringify(arr));
//		} else {
//			$('#callParameter').val("");
//		}

    	$.ajax({
    		url: "./authRuleList",
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
	 * 会社コード選択ボタン押下（open modal）
	 */
	$('#companySelect').on('click', function(e){
		//alert("click [companySelect]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//会社選択モーダル画面呼び出す
		$('#callFrom').val('companySelect');
		$('#callParameter').val(splitToJsonStr('companyCode', 'companyCode'));
		$('#callReturn').val("");
		$.ajax({
    		url: "./authComCodeList",
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
		document.getElementById("ActionErrorMessage").style.display="none";

	});

	/**
	 * 雇用区分コード選択ボタン押下（open modal）
	 */
	$('#employmentKbnSelect').on('click', function(e){
		//alert("click [employmentKbnSelect]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//雇用区分選択モーダル画面呼び出す
		$('#callFrom').val('employmentKbnSelect');
		$('#callParameter').val(splitToJsonStr('employmentCode', 'employmentCode'));
		$('#callReturn').val("");
		$.ajax({
    		url: "./authEmpCodeList",
    		type: "POST",
    		data: $('#dialogParamForm').serialize(),
    		success: function(result){
    			$("#modal_dailog_body").html(result);
        		$("#listModal").modal('show');
        		//ボタン押下開放
        		isPosting = false;
    		},
            error: function(err){
				console.log(err);
				//ボタン押下開放
				isPosting = false;
			}
		});
		document.getElementById("ActionErrorMessage").style.display="none";

    });

	/**
	 * 組織コード選択ボタン押下（open modal）
	 */
	$('#organizationSelect').on('click', function(e){
		//alert("click [organizationSelect]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//組織選択モーダル画面呼び出す
		$('#callFrom').val('organizationSelect');
		$('#callParameter').val(splitToJsonStr('organizationCode', 'companyCode', 'organizationCode'));
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
				console.log(err);
				//ボタン押下開放
				isPosting = false;
            }
		});
		document.getElementById("ActionErrorMessage").style.display="none";
    });

	/**
	 * 役職コード選択ボタン押下（open modal）
	 */
	$('#postionSelect').on('click', function(e){
		//alert("click [positionSelect]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//役職選択モーダル画面呼び出す
		$('#callFrom').val('positionSelect');
		$('#callParameter').val(splitToJsonStr('positionCode', 'companyCode', 'positionCode'));
		$('#callReturn').val("");
    	$.ajax({
    		url: "./authPosCodeList",
    		type: "POST",
    		data: $('#dialogParamForm').serialize(),
    		success: function(result){
    			$("#modal_dailog_body").html(result);
        		$("#listModal").modal('show');
        		//ボタン押下開放
        		isPosting = false;
    		},
            error: function(err){
				console.log(err);
				//ボタン押下開放
				isPosting = false;
            }
		});
		document.getElementById("ActionErrorMessage").style.display="none";

	});


	/**
	 * ユーザーID選択ボタン押下（open modal）(付与)
	 */
	$('#userSelect').on('click', function(e){
		//alert("click [userSelect]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//ユーザー選択モーダル画面呼び出す
		$('#callFrom').val('userSelect');
		$('#callParameter').val(splitToJsonStr('userCode', 'userCode'));
		$('#callReturn').val("");
    	$.ajax({
    		url: "./authUserCodeList",
    		type: "POST",
    		data: $('#dialogParamForm').serialize(),
    		success: function(result){
    			$("#modal_dailog_body").html(result);
        		$("#listModal").modal('show');
        		//ボタン押下開放
        		isPosting = false;
    		},
            error: function(err){
				console.log(err);
				//ボタン押下開放
				isPosting = false;
            }
		});
		document.getElementById("ActionErrorMessage").style.display="none";

	});


	/**
	 * ユーザーID選択ボタン押下（open modal）(除外)
	 */
	$('#userExtSelect').on('click', function(e){
		//alert("click [userSelect]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//ユーザー選択モーダル画面呼び出す
		$('#callFrom').val('userExtSelect');
		$('#callParameter').val(splitToJsonStr('userExtCode', 'userCode'));
		$('#callReturn').val("");
    	$.ajax({
    		url: "./authUserCodeList",
    		type: "POST",
    		data: $('#dialogParamForm').serialize(),
    		success: function(result){
    			$("#modal_dailog_body").html(result);
        		$("#listModal").modal('show');
        		//ボタン押下開放
        		isPosting = false;
    		},
            error: function(err){
				console.log(err);
				//ボタン押下開放
				isPosting = false;
            }
		});
		document.getElementById("ActionErrorMessage").style.display="none";

	});

	/**
	 * グループ検索ボタン押下（open modal）
	 */
	$('#groupSelect').on('click', function(e){
		//alert("click [groupSelect]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//グループ選択モーダル画面呼び出す
		$('#callFrom').val('groupSelect');
		//グループ一覧のJson文字列を作成、削除済のグループIDを除く
		$('#callParameter').val(tableToJsonStr('hgroupId_', 'groupId', 'hdelFlg_'));
		$('#callReturn').val("");
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
            error: function(err){
				console.log(err);
				//ボタン押下開放
				isPosting = false;
            }
		});
		document.getElementById("ActionErrorMessage").style.display="none";
    });

	/**
	 * ルール保存ボタン押下（open modal）
	 */
	$("#ruleUpdate").click(function(e){
		//alert("click [ruleUpdate]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//ルール条件設定を一覧に未反映の場合
		var m = "<p> 表示されたルールが保存されます。<br />よろしいですか？</p>";
		if ($('#editFlg').val() == '1') {
			m = "<p> 編集されたルール条件が設定済条件一覧に反映されていません。<br />一覧に反映しないと編集の内容は破棄されます。<br />よろしいですか？";
		}
		authRuleSetConfirm( e, m,
			function(){
				$('#authRuleSetForm').attr('action','./authRuleSetSave');
		        $('#authRuleSetForm').submit();
			});
		//ボタン押下開放
		isPosting = false;
	});

	/**
	 * ルール削除ボタン押下（open modal）
	 */
	$("#ruleDelete").click(function(e){
		//alert("click [ruleDelete]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		var m = "<p> 検索で表示されたルールが削除されます。<br />よろしいですか？</p>";
		authRuleSetConfirm( e, m,
			function(){
				$('#authRuleSetForm').attr('action','./authRuleSetDelete');
				$('#authRuleSetForm').submit();
			});
		//ボタン押下開放
		isPosting = false;
	});


	/**
	 * クリアボタン押下
	 */
	$("#ruleClear").click(function(e){
		//alert("click [ruleClear]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		var m = "変更内容が登録されていません。<br />保存を行わない場合、変更内容は破棄されます。<br />よろしいですか？";
		if ($("#changedFlg").val() == '1' || $("#editFlg").val() == '1') {
			authRuleSetConfirm( e, m,
					// 確定ボタン押下の場合、初期化処理する
					function(){
						$('#authRuleSetForm').attr('action','./authRuleSetClear');
						$('#authRuleSetForm').submit();
				   });
		}else{
			//初期化処理する
			$('#authRuleSetForm').attr('action','./authRuleSetClear');
			$('#authRuleSetForm').submit();
		}
		//ボタン押下開放
		isPosting = false;
	});


	/**
	 * ルール条件セレクトチャンジン　
	 */
	$("#ruleSelectOpt").change(function(e){

		var selectVal = $(this).find("option:selected").val();

		//セレクトの値が0：新規条件,1:既存条件を判定
		var chk = selectVal.split('-');
		if (chk.length != 2) {
			var p = document.getElementById("ActionErrorMessage");
			p.style.display="block";
			p.innerHTML = " <p> システムエラー：　ルール条件ドロップダウンの値が不正(" + selectVal + ") </p>";
			window.scrollTo( 0, 0 );
			return false;
		}

		if(chk && chk[0] == '0'){
			//条件入力エリアクリア
			$('#companyCode').val("");
			$('#employmentCode').val("");
			$('#organizationCode').val("");
			$('#positionCode').val("");

			//一覧から削除ボタン押下不可
			$('#deleteFrList').prop("disabled",true);
		} else {
			//リストから条件取得して入力エリアにセット
			var idx = chk[0]-1;
			var kbn = chk[1];

			if (kbn=='0') {
				$('#companyCode').val($('#hcompanySet_'+idx).val());
				$('#employmentCode').val($('#hemploymentSet_'+idx).val());
				$('#organizationCode').val($('#horganizationSet_'+idx).val());
				$('#positionCode').val($('#hpositionSet_'+idx).val());
			} else {
				$('#companyCode').val($('#hcompanyExt_'+idx).val());
				$('#employmentCode').val($('#hemploymentExt_'+idx).val());
				$('#organizationCode').val($('#horganizationExt_'+idx).val());
				$('#positionCode').val($('#hpositionExt_'+idx).val());
			}
			//一覧から削除ボタン押下可
			$('#deleteFrList').prop("disabled",false);
		}
		$('#currentOptNo').val(chk[0]);
		$('#currentOptKbn').val(chk[1]);
		$('#currentOptValue').val($(this).find("option:selected").text());

		document.getElementById("ActionErrorMessage").style.display="none";

	});


	/**
	 * 一覧反映ボタン押下
	 */
	$("#updateToList").click(function(e){
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		var selectVal = $('#ruleSelectOpt').find("option:selected").val();

		//セレクトの値が0：新規条件,1:既存条件を判定
		var chk = selectVal.split('-');
		if (chk.length != 2) {
			var p = document.getElementById("ActionErrorMessage");
			p.style.display="block";
			p.innerHTML = " <p> システムエラー：　ルール条件が不正(" + selectVal + ") </p>";
			window.scrollTo( 0, 0 );

			isPosting = false;
			return false;
		}

		//値存在チェック: テキストエリアにデータ存在しない場合、エラーメッセージ表示
		if ($.trim($('#companyCode').val()) == ""
			&& $.trim($('#employmentCode').val()) == ""
			&& $.trim($('#organizationCode').val()) == ""
			&& $.trim($('#positionCode').val()) == ""
		) {
			var p = document.getElementById("ActionErrorMessage");
			p.style.display="block";
			p.innerHTML = " <p> ルール設定条件が未入力エラー、先にコード選択ボタン押下してルール設定条件を入力してください。 </p>";
			window.scrollTo( 0, 0 );

			isPosting = false;
			return false;
		}

		var m = " <p> 選択したルール条件が設定済条件一覧に反映されます。<br />よろしいですか？</p>";
		authRuleSetConfirm(e, m,
			function() {
				updateConditionListRec();
			});

		document.getElementById("ActionErrorMessage").style.display="none";
		isPosting = false;
	});

	/**
	 * 一覧から削除ボタン押下
	 */
	$("#deleteFrList").click(function(e){
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		var selectVal = $('#ruleSelectOpt').find("option:selected").val();
		//セレクトの値が0（新規）の場合
		var chk = selectVal.split('-');

		if (chk.length != 2) {
			var p = document.getElementById("ActionErrorMessage");
			p.style.display="block";
			p.innerHTML = " <p> システムエラー：　ルール条件ドロップダウンの値が不正(" + selectVal + ") </p>";
			window.scrollTo( 0, 0 );

			isPosting = false;
			return false;
		}

		if(chk && chk[0] == '0'){
			var p = document.getElementById("ActionErrorMessage");
			p.style.display="block";
			p.innerHTML = " <p> 削除対象条件が正しく選択されていません。対象の条件を選択してください。</p>";
			window.scrollTo( 0, 0 );

			isPosting = false;
			return false;
		}

		var m = " <p> 選択したルール条件が設定済条件一覧から削除されます。<br />よろしいですか？</p>";
		authRuleSetConfirm(e, m,
			function() {
				deleteConditionListRec();
			});

		document.getElementById("ActionErrorMessage").style.display="none";
		isPosting = false;
	});

	/**
	 * 設定済条件一覧にデータ反映
	 */
	function updateConditionListRec() {
		//console.log('doaction  authRuleSetUpdateList');
		//コード選択の入力状態をクリア
		$('#editFlg').val('');

		$('#authRuleSetForm').attr('action','./authRuleSetUpdateList');
		$('#authRuleSetForm').submit();
	}

	/**
	 * 設定済条件一覧からデータ削除
	 */
	function deleteConditionListRec() {
		//コード選択の入力状態をクリア
		$('#editFlg').val('');

		$('#authRuleSetForm').attr('action','./authRuleSetDeleteList');
		$('#authRuleSetForm').submit();
	}

    /**
     * ボタン押下時確認ダイヤログメッセージ
     */
	function authRuleSetConfirm(e,message,okcallback,ngcallback) {
		var that = this;
		var confirmText = "変更内容が登録されていません。<br />保存を行わない場合、変更内容は破棄されます。<br />よろしいですか？"
		if (message) {
			confirmText = message;
		}
        //既存のダイアログエリア削除
        $('#comfirmDialog').remove();
		var $div = $("<div id='comfirmDialog'><span>" + confirmText + "</span></div>");
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
			open:function(event, ui){
				$(".ui-dialog-titlebar-close").hide();
			},
			close:function(event, ui){
				$('#comfirmDialog').remove();
			}
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
			authRuleSetConfirm(e, m,
				function(){
					$("#changedFlg").val('');
					$("#editFlg").val('');
					window.location.href = $(that).attr("href");
					console.log("href:" + window.location.href);
				});
		}
	});

	/**
	 * JSONオブジェクトの文字列作成
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
		console.log(JSON.stringify(r));
		return JSON.stringify(r);
	};

	/**
	 * Table指定列のJSONオブジェクトの文字列作成
	 */
	function tableToJsonStr(id, item, delflg) {
		var arr = $('input[id^="'+id+'"]');
		var del = $('input[id^="'+delflg+'"]');

		var r = [];
		var idx=0;
		for(var idx=0; idx<arr.length; idx++) {
			if (del[idx] && 'true'==del[idx].value) {
				continue;
			}
			var rs = {};
			rs[item] = arr[idx].value;
			r.push(rs);
		}

		console.log(JSON.stringify(r));
		return JSON.stringify(r);
	}
});
