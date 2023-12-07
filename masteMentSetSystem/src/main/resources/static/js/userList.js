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

namespace('axio.userList');

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

	// 画面初期表示、チェックボックス設定
	if ($('#InvUserFlg').val() === "ON") {
		// チェック
		$('#InvUserCheckBox').prop('checked', true);
	} else {
		// チェックを外す
		$('#InvUserCheckBox').prop('checked', false);
	}

	// 画面初期表示、検索結果が1件以上の場合、CSVダウンロードボタン押下可能、並び順設定
	if ($('.jstableLink').length > 0) {
		$("#downloadBtn").removeClass("searchBox__titleArea__button_dis");
		$("#downloadBtn").addClass("searchBox__titleArea__button");
        // 並び順設定
		setOrder();
	}

/**
 * チェックボックス値が更新された場合
 */
	$('#InvUserCheckBox').change(function() {
	    // チェックの状態を取得
	    var prop = $('#InvUserCheckBox').prop('checked');

	    if (prop) {
	      $('#InvUserFlg').val('ON');
	    } else {
	      $('#InvUserFlg').val('OFF');
	    }
	  });

    // 検索結果が100件を超える場合
	if ($("#popupShowFlg").val() == "ON") {
		var m = $("#popupMsg").val();

		userListConfirm(null, m, function(){
			//検索処理
			$.ajax({
	    		url: "./userListSearch",
	    		type: "POST",
	    		data: $("#userListForm").serialize(),
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
		},
		function(){
			$("#countCheck").val("");
			$("#popupShowFlg").val("");
		}

		);
	}

    /** ユーザリスト検索 */
	function search(e){
		//alert("click [dailogGroupSearch]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//検索処理
		$.ajax({
    		url: "./userListSearch",
    		type: "POST",
    		data: $("#userListForm").serialize(),
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
	};

    /** ユーザリスト検索 */
	function searchBySort(e){
		//alert("click [dailogGroupSearch]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//検索処理
		$.ajax({
    		url: "./userListChangeOrder",
    		type: "POST",
    		data: $("#userListForm").serialize(),
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
	};

    /** ユーザリスト検索 */
	function download(e){
		//alert("click [dailogGroupSearch]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//検索処理
		$.ajax({
    		url: "./userListDownload",
    		type: "POST",
    		data: $("#userListForm").serialize(),
    		success: function(result){
    			//ボタン押下開放
    			isPosting = false;

    		},
			error: function(err) {
				//ボタン押下開放
				isPosting = false;
			}
		});
	};

    /** ユーザリスト検索 */
	function changeShow(name){
		var itemName = "#" + name;
		$(itemName).toggleClass("is-on");
		$(itemName).toggleClass("is-hide");

	};

	/**
	 * 検索ボタン押下
	 */
	$('#search').on('click', function(e){
		search(e);
    });

	/**
	 * PopUp画面にて、「OK」ボタンを押下
	 */
	$('#popup_ok').on('click', function(e){
		search(e);
    });

	/**
	 * クリアボタン押下
	 */
	$('#clear').on('click', function(e){
		$("#condition input[type='text']").val("");
		$("#condition input[type='checkbox']").prop('checked',false);
    });

	/**
	 * 詳細表示ボタン押下
	 */
	$('#detailConditionBtn').click(function() {
		$("#detailConditionBtn").toggleClass("is-on");
		$("#detailCondition").toggleClass("is-hide");
	});

	/**
	 * CSVボタン押下
	 */
	$('#downloadBtn').click(function(e) {
		var m = "<p>検索結果のCSV出力を開始します。<br/>よろしいですか？</p>";

		userListConfirm(e, m,
				function(){
					$('#userListForm').attr('action', './userListDownload');
					$('#userListForm').submit();
				});
	});

	/**
	 * 詳細画面遷移
	 */
	$('.jstableLink td').click(function(e) {
		$('#curRowId').val(e.target.parentElement.id);
		$('#userListForm').attr('action','./userSetMove');
		$('#userListForm').submit();
	});

	/**
	 * 前のページボタン押下
	 */
	$('#prePageBtn').click(function(e) {
		//alert("click [dailogGroupSearch]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//検索処理
		$.ajax({
    		url: "./userListShowPrePage",
    		type: "POST",
    		data: $("#userListForm").serialize(),
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

	/**
	 * 後ページボタン押下
	 */
	$('#nextPageBtn').click(function(e) {
		//alert("click [dailogGroupSearch]");
		//通常のアクションをキャンセルする
		e.preventDefault();
		//処理中、ボタン押下の抑制
		if (isPosting) return false;
		isPosting = true;

		//検索処理
		$.ajax({
    		url: "./userListShowNextPage",
    		type: "POST",
    		data: $("#userListForm").serialize(),
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

	/**
	 * 並び順更新して、再検索する
	 */
	$('#orderBar > th > button').click(function(e) {
		// 並び順iconを変更
		var order;

		if($(this).hasClass('default')){
			order = 'desc';
		} else if($(this).hasClass('desc')){
			order = 'asc';
		} else if($(this).hasClass('asc')){
			order = 'desc';
		}

		$('#orderBar > th > button').removeClass('desc asc');
		$('#orderBar > th > button').addClass('default');

		$(this).removeClass('default');
		$(this).addClass(order);
		// 並び順リストを保存
		saveOrder();
        // 再検索する
		searchBySort(e);

	});

	/**
	 * 並び順整理
	 */
	function setOrder(){
		// ボタン押下可能
		$('#orderBar button').removeAttr('disabled');

		// 降順／昇順iconを設定する
		var sortCondition = $('#sortCondition').val();
		const list = sortCondition.split(",");

		$('#orderBar').find('th').find('button').each(function( index, value ) {
		    if(list[index] == 'ASC'){
				$(this).addClass('asc');

		    } else if(list[index] == 'DESC'){
				$(this).addClass('desc');

		    } else{
				$(this).addClass('default');

		    }
		})
	};

	/**
	 * 並び順整理
	 */
	function saveOrder(){
		var sort = [];

		$('#sortCondition').val(sort);

		$('#orderBar').find('th').find('button').each(function( index, value ) {
		    if($(this).hasClass('asc')){
		    	sort.push('ASC');

		    } else if($(this).hasClass('desc')){
		    	sort.push('DESC');

		    } else {
		    	sort.push('');
		    }
		})

		$('#sortCondition').val(sort);
	};

    /**
     * ボタン押下時確認ダイヤログメッセージ
     */
	function userListConfirm(e,message,okcallback,ngcallback) {
		var that = this;
		if (message) {
			confirmText = message;
		}
        //既存のダイアログエリア削除
        $('#comfirmDialog').remove();
		var $div = $("<div id='comfirmDialog'><span>" + confirmText + "</span></div>");

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
});
