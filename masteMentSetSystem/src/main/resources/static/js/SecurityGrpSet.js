
/**
 * 名前空間を作成します。
 * 既に存在している階層については作成しません。
 * @prame ns .区切りの名前空間文字列
 * 依存関係については、requiere.jsでの管理やgulpのpolify等は行いません。
 * また、オブジェクトの階層によって、ライブラリを管理し必要に応じて即時関数を利用しグローバル領域を安全に保ってください。
 */
namespace = function (ns) {
	var o = null;
	var unit = ns.split(".");
	o = window;
	for (var j = 0; j < unit.length; j = j + 1) {
		o[unit[j]] = o[unit[j]] || {};
		o = o[unit[j]];
	}
	return o;
};

namespace('axio.securityGrpSet');

$(function () {
	var isPosting = false;

	$(".dpickDateCalendar").datepicker({
		showButtonPanel: false		// 「Today」「Done」ボタン 無効
		, changeMonth: false 		// 「月」リスト選択 無効
		, changeYear: false			// 「年」リスト選択 無効
		, dateFormat: "yy/mm/dd"		// 日付フォーマット yyyy/MM/dd
		, firstDay: 0 			 	// 週の最初の曜日 0:日曜日
		, beforeShow: function (elem, dp) {
			dp.dpDiv.css('z-index', '1051');
		}
	});


	/**
	 * テキストボックスの値（input type=text）の変更がある場合
	 */
	$('input[type="text"]').change(function (e) {
		$("#changedFlg").val('1');
	});

	/**
	 * 日付ボックスの値（input type=dpickDateCalendar）の変更がある場合
	 */
	$('input[type="dpickDateCalendar"]').change(function (e) {
		$("#changedFlg").val('1');
	});

	/**
	 * チェックボックスの値（input type=checkbox）の変更がある場合
	 */
	$('input[type="checkbox"]').change(function (e) {
		$("#changedFlg").val('1');
	});

	//警告メッセージダイアログの表示
	if ($("#wanMessage").val() != '') {
		$("#axioWanDialog").dialog({
			modal: true,
			buttons: [
				{
					text: 'OK',
					class: 'btn',
					click: function () {
						$(this).dialog("close");
						var url = $('#wanUrl').val();
						// 警告確認済みフラグ
						$('#wanCheck').val("1");
						$('#wanMessage').val("");
						$('#SecurityGrpSetForm').attr('action', url);
						$('#SecurityGrpSetForm').submit();

					}
				},
				{
					text: 'キャンセル',
					class: 'btn',
					click: function () {
						$(this).dialog("close");
						$('#wanCheck').val("0");
						$('#wanMessage').val("");
					}
				}
			],
			open: function (event, ui) {
				$(".ui-dialog-titlebar-close").hide();
			},
			close: function (event, ui) {
				$('#axioErrDialog').remove();
			}
		});
	}


	//エラーメッセージダイアログの表示
	if ($("#errMessage").val() != '') {
		$("#axioErrDialog").dialog({
			modal: true,
			buttons: [
				{
					text: 'OK',
					class: 'btn',
					click: function () {
						$(this).dialog("close");
					}
				}
				
			],
			open: function (event, ui) {
				$(".ui-dialog-titlebar-close").hide();
			},
			close: function (event, ui) {
				$('#axioErrDialog').remove();
			}
		});
	}


	// メニュー切り替え
	$('#securityGrpSetLink').on('click', function (e) {
		//通常のアクションをキャンセルする
		e.preventDefault();

		//変更ある場合、確認メッセージ表示
		var message = "変更内容が登録されていません。<br />保存を行わない場合、変更内容は破棄されます。<br />よろしいですか？";
		if ($("#changedFlg").val() == '1' || $("#editFlg").val() == '1') {
			showConfirm(e, message,
				// 確定ボタン押下の場合、グループ検索モーダル画面呼び出す
				function () {
					document.location = "./securityGrpSet";
				});
		} else {
			// グループ検索モーダル画面呼び出す
			document.location = "./securityGrpSet";
		}

	});

	// メニュー切り替え
	$('#securityGrpRegLink').on('click', function (e) {
		//通常のアクションをキャンセルする
		e.preventDefault();

		//変更ある場合、確認メッセージ表示
		var message = "変更内容が登録されていません。<br />保存を行わない場合、変更内容は破棄されます。<br />よろしいですか？";
		if ($("#changedFlg").val() == '1' || $("#editFlg").val() == '1') {
			showConfirm(e, message,
				// 確定ボタン押下の場合、グループ検索モーダル画面呼び出す
				function () {
					document.location = "./securityGrpReg"
				});
		} else {
			// グループ検索モーダル画面呼び出す
			document.location = "./securityGrpReg"
		}

	});



	/**
	 * ダイヤログコールバック
	 */
	axio.securityGrpSet.dailogCallback = function dailogCallback(res, err) {

		var cfrom = $('#callFrom').val();

		//コード選択ダイヤログ画面から戻した場合
		$('#editFlg').val('1');

		if (err) {
			$('#ActionErrorText').val(err);
			$('#ActionErrorMessage').show();
		} else {
			const obj = res ? JSON.parse(res) : null;
			if (obj.length > 0) {
				parseOrganizationRetVal(obj);
				// search(this);
			}
		}
	}

	/**
	 * 組織コード選択ボタン押下（open modal）
	 */
	$('#companySearch').on('click', function (e) {
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//組織選択モーダル画面呼び出す
		$('#callFrom').val('companySearch');
		$('#callParameter').val("");
		$('#callReturn').val("");
		$.ajax({
			url: "./authOrgCodeList",
			type: "POST",
			data: $('#dialogParamForm').serialize(),
			success: function (result) {
				$("#modal_dailog_body").html(result);
				$("#listModal").modal('show');
				//ボタン押下開放
				isPosting = false;
			},
			error: function (err) {
				//ボタン押下開放
				isPosting = false;
			}
		});
	});


	/**
	 * 戻るボタン押下
	 */
	$("#backbtn").on('click', function (e) {

		//変更ある場合、確認メッセージ表示
		var message = "セキュリティグループ情報の変更があります。<br/>保存せずにメニュー画面に戻りますか？";
		if ($("#changedFlg").val() == '1' || $("#editFlg").val() == '1') {
			showConfirm(e, message,
				// 確定ボタン押下の場合、メニューに遷移する
				function () {
					$('#SecurityGrpSetForm').attr('action', './login');
					$('#SecurityGrpSetForm').submit();
				});
		} else {
			// グループ検索モーダル画面呼び出す
			$('#SecurityGrpSetForm').attr('action', './login');
			$('#SecurityGrpSetForm').submit();
		}

	});


	/**
	 * 組織SG設定保存
	 */
	$('#setSaveBtn').on('click', function (e) {
		// 通常のアクションをキャンセルする
		e.preventDefault();
		// 処理中、ボタン押下の抑制
		if (isPosting) return false;

		isPosting = true;

		var message = "<p>セキュリティグループ情報が保存されます。<br/> よろしいですか？</p>";

		// 保存処理を行う
		showConfirm(e, message,
			function () {
				// 設定されていない場合更新
				$('#SecurityGrpSetForm').attr('action', './securityGrpSetSave');
				$('#SecurityGrpSetForm').submit();
			});

		$("#changedFlg").val('0');

		isPosting = false;
	});

	/**
	 * 組織SG設定解除
	 */
	 $('#organizationClear').on('click', function (e) {
		// 通常のアクションをキャンセルする
		e.preventDefault();
		// 処理中、ボタン押下の抑制
		if (isPosting) return false;

		isPosting = true;

		var message = "<p>組織の紐づき設定を解除します。<br/> よろしいですか？</p>";

		// 保存処理を行う
		showConfirm(e, message,
			function () {
				// 設定されていない場合更新
				$('#SecurityGrpSetForm').attr('action', './securityGrpSetClear');
				$('#SecurityGrpSetForm').submit();
			});

		$("#changedFlg").val('0');

		isPosting = false;
	});


	// 表のオープンクローズ
	$(".jsAccordionTable").on('click', function () {

		$(this).toggleClass("is-on");
		$(this).next(".jsViewTable").toggleClass("is-hide");
		icon = $(this).find('.fa-solid');
		$(icon).toggleClass("fa-angle-down");
		$(icon).toggleClass("fa-angle-up");


		// $(this).next('table').fadeIn();

	});


	// テーブルにカーソルがあるときに、否時SGIDでハイライトする
	// 組織未設定のセキュリティグループ配下
	$('.setup_org__list_not .sgrow').hover(
		function () {
			//マウスカーソルが重なった時の処理
			$('[data-sgid="' + $(this).data().sgid + '"]').toggleClass("sgrow_highlight");

		},
		function () {
			//マウスカーソルが離れた時の処理
			$('[data-sgid="' + $(this).data().sgid + '"]').toggleClass("sgrow_highlight");

		}

	);

	// テーブルにカーソルがあるときに、否時SGIDでハイライトする
	// 組織未設定のセキュリティグループ配下
	$('.setup_org__list .sgrow').hover(
		function () {
			//マウスカーソルが重なった時の処理
			$('[data-sgid="' + $(this).data().sgid + '"][data-cpcd="' + $(this).data().cpcd + '"][data-orgcd="' + $(this).data().orgcd + '"]').toggleClass("sgrow_highlight");

		},
		function () {
			//マウスカーソルが離れた時の処理
			$('[data-sgid="' + $(this).data().sgid + '"][data-cpcd="' + $(this).data().cpcd + '"][data-orgcd="' + $(this).data().orgcd + '"]').toggleClass("sgrow_highlight");
		}

	);


	/**
	 * 組織選択ボタン押下（open modal）
	 */
	$('#select_org').on('click', function (e) {

		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//変更ある場合、確認メッセージ表示
		var m = "変更内容が登録されていません。<br />保存を行わない場合、変更内容は破棄されます。<br />よろしいですか？";
		if ($("#changedFlg").val() == '1' || $("#editFlg").val() == '1') {
			authRuleSetConfirm(e, m,
				// 確定ボタン押下の場合、組織選択モーダル画面呼び出す
				function () {
					setTimeout(function () { searchRuleData(); }, 0);
				});
		} else {
			//組織選択モーダル画面呼び出す
			setTimeout(function () { searchRuleData(); }, 0);
		}
		//ボタン押下開放
		isPosting = false;
	});


	/**
	 * 組織コード選択ボタン押下（open modal）
	 */
	$('#organizationSelect').on('click', function (e) {

		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//組織選択モーダル画面呼び出す
		$('#callFrom').val('companySearch');
		// $('#callParameter').val(splitToJsonStr('organization'));
		$('#callParameter').val("");
		$('#callReturn').val("");
		$.ajax({
			url: "./authOrgCodeList",
			type: "POST",
			data: $('#dialogParamForm').serialize(),
			success: function (result) {
				$("#modal_dailog_body").html(result);
				$("#listModal").modal('show');
				//ボタン押下開放
				isPosting = false;
			},
			error: function (err) {
				//ボタン押下開放
				isPosting = false;
			}
		});
	});

	/**
	 * グループ検索ボタン押下
	 */
	$('#groupSearch').on('click', function (e) {
		//alert("click [groupRegistSearch]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//変更ある場合、確認メッセージ表示
		var message = "変更内容が登録されていません。<br />保存を行わない場合、変更内容は破棄されます。<br />よろしいですか？";
		if ($("#changedFlg").val() == '1' || $("#editFlg").val() == '1') {
			showConfirm(e, message,
				// 確定ボタン押下の場合、グループ検索モーダル画面呼び出す
				function () {
					setTimeout(function () { searchGroupData(); }, 0);
				});
		} else {
			// グループ検索モーダル画面呼び出す
			setTimeout(function () { searchGroupData(); }, 0);
		}
		//ボタン押下開放
		isPosting = false;
	});


	/**
	 * セキュリティグループ選択ボタン押下
	 */
	$('.select_btn').on('click', function (e) {

		//通常のアクションをキャンセルする
		e.preventDefault();

		$("#overlay").fadeIn(100);

		
		// 選択されたSGIDを取得
		selectTr = $(this).parent().parent()[0];
		$("#selectSecurityGrpCode").val($(selectTr).data().sgid);
		$("#companyCode").val($(selectTr).data().cpcd);
		$("#organizationCode").val($(selectTr).data().orgcd);

	
		// セキュリティグループ選択
		$('#SecurityGrpSetForm').attr('action', './securityGrpSetSelect');
		$('#SecurityGrpSetForm').submit();
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

		$.ajax({
			url: "./securityGroupList",
			type: "POST",
			data: $('#dialogParamForm').serialize(),
			success: function (result) {
				$("#modal_dailog_body").html(result);
				$("#listModal").modal('show');
				//ボタン押下開放
				isPosting = false;
			},
			error: function (err) {
				console.log(err);
				//ボタン押下開放
				isPosting = false;
			}
		});
	}

})



/* 下記は呼び出す用function*/

/**
 * 組織コードテキスト欄をフラッシュ
 */
function parseOrganizationRetVal(o) {
	var v = '';
	if (o) {
		//一覧画面からの戻り値をセット
		for (var i = 0; i < o.length; i++) {
			// テキストエリアに値をセット
			var company = o[i].company;
			var organization = o[i].organization + ':' + o[i].name;
			var orgCode = o[i].organization;
			var orgName = o[i].name

			// テキストエリアに値をセット
			$('#companyCodeText').text(company);
			$('#organizationCodeText').text(orgCode);
			$('#organizationNameText').text(orgName);

			$('#companyCode').val(company);
			$('#organizationCode').val(orgCode);
			$('#organizationName').val(orgName);

		}
	}
}

/**
 * ユーザリスト検索
 */
function search(e) {
	$('#SecurityGrpSetForm').attr('action', './securityGrpSetRedraw');
	$('#SecurityGrpSetForm').submit();
};

/**
 *
 * @returns
 */
function isChanged() {

	if ($('#companyCode').val() != "" || $('#organizationCodeName').val() != "") {
		// セキュリティグループ名
		var grpFlag;
		if ($("#grpFlag1").prop("checked")) grpFlag = "1";
		if ($("#grpFlag2").prop("checked")) grpFlag = "2";

		if (grpFlag != $('#groupFlag_hd').val()) {
			return true;
		} else {
			if (grpFlag == "2" &&
				$("#groupName_hd").val() != $("#manualGrpName").val()) {
				return true;
			}
		}

		// 管理職セキュリティグループ
		var mangGroupFlg;

		if ($("#mangGroupFlg1").prop("checked")) mangGroupFlg = "1";
		if ($("#mangGroupFlg2").prop("checked")) mangGroupFlg = "0";

		if (mangGroupFlg != $('#mangGroupFlg_hd').val()) {
			alert("管理職セキュリティグループ変更あり");

			return true;
		}

		//メールセキュリティグループ名
		var mailGrpFlag;
		if ($("#mailGrpFlag1").prop("checked")) mailGrpFlag = "1";
		if ($("#mailGrpFlag2").prop("checked")) mailGrpFlag = "2";

		if (mailGrpFlag != $('#mailGroupFlg_hd').val()) {
			return true;
		} else {
			if (mailGrpFlag == "2" &&
				$("#mailGroupName_hd").val() != $("#ManualmailGrpName").val()) {
				return true;
			}
		}

		// 従業員区分比較
		var dispatchSetFlag;

		if ($("#dispatchSetFlag1").prop("checked")) dispatchSetFlag = "0";
		if ($("#dispatchSetFlag2").prop("checked")) dispatchSetFlag = "1";

		if (dispatchSetFlag != $('#excludeTempFlag_hd').val()) {
			return true;
		}

		// 反映日比較
		if ($('#reflectDate').val() != $('#reflectDate_hd').val()) {
			return true;
		}
	}
	return false;
}

/**
 *  ダイヤログ画面
 * @param e
 * @param message
 * @param okcallback
 * @param ngcallback
 * @returns
 */
function showConfirm(e, message, okcallback, ngcallback) {
	var that = this;
	//既存のダイアログエリア削除
	$('#comfirmDialog').remove();
	var $div = $("<div id='comfirmDialog'><span>" + message + "</span></div>");

	if (e != null) {
		e.preventDefault();
	}

	$div.dialog({
		title: '確認',
		autoOpen: false,
		modal: true,
		buttons: [
			{
				text: 'OK',
				class: 'btn',
				click: function () {
					preventEvent = false;
					$(this).dialog("close");
					if (okcallback) {
						okcallback();
					}
				}
			},
			{
				text: 'キャンセル',
				class: 'btn',
				click: function () {
					if (ngcallback) {
						ngcallback();
					}
					$(this).dialog("close");
				}
			}
		],
		open: function (event, ui) {
			$(".ui-dialog-titlebar-close").hide();
		},
		close: function (event, ui) {
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
		modal: true,
		autoOpen: false,
		modal: true,
		title: title,
		buttons: [
			{
				text: 'OK',
				class: 'btn',
				click: function () {
					preventEvent = false;
					$(this).dialog("close");
				}
			}
		],
		open: function (event, ui) {
			$(".ui-dialog-titlebar-close").hide();
		},
		close: function (event, ui) {
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
	console.log($('#' + id).val());
	var s = $('#' + id).val().split(';');
	var r = [];
	$.each(s, function (ind, v) {
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


// $("#overlay").fadeIn(100);


/** ユーザリスト検索 */
// function changeShow(name){
// 	var itemName = "#" + name;
// 	$(itemName).toggleClass("is-on");
// 	$(itemName).toggleClass("is-hide");

// };

