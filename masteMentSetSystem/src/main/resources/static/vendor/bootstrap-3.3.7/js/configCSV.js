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

namespace('ams.configCSV');

$(function() {
	/**
	 * 再描画submit処理
	 * class属性にsubmitボタンが設定されている要素をクリックされた際にdata-action属性へ指定されたurlへform送信
	 */
	$("#redraw ,#clear").on("click", function() {
		if($("#changedDataRedrawFlg").val()){
			// 確認メッセージ表示
			var $btn = $(this);
			var $div = $('<div id="_dialogLeave"><span>保存されていないため、入力した内容が破棄されますが宜しいでしょうか</span></div>');

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
							if ($btn.data('action')) {
								$("#changedDataRedrawFlg").val("");
								$btn.parents('form').attr('action', $btn.data('action'));
								$btn.parents('form').submit();
							}
							$(this).dialog("close");
						}
					},
					{
						text: 'キャンセル' ,
						class: 'btn' ,
						click: function(){
							$(this).dialog("close");
						}
					}
				],
				open:function(event, ui){ $(".ui-dialog-titlebar-close").hide();}
			});
			$div.dialog('open');
		}else if ($(this).data('action')) {
			// メッセージなしのsubmit
			$(this).parents('form').attr('action', $(this).data('action'));
			$(this).parents('form').submit();
		}
	});

	/**
	 * SQL出力submit処理
	 * class属性にsubmitボタンが設定されている要素をクリックされた際にdata-action属性へ指定されたurlへform送信
	 */
	$("#outSQL").on("click", function() {
		if($("#changedDataOutSqlFlg").val()){
			// 確認メッセージ表示
			var $btn = $(this);
			var $div = $('<div id="_dialogLeave"><span>保存されていないため、入力した内容が破棄されますが宜しいでしょうか</span></div>');

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
							if ($btn.data('action')) {
								$("#changedDataOutSqlFlg").val("");
						    	$('#outputInfo option').prop("selected",true);
								$btn.parents('form').attr('action', $btn.data('action'));
								$btn.parents('form').submit();
							}
							$(this).dialog("close");
						}
					},
					{
						text: 'キャンセル' ,
						class: 'btn' ,
						click: function(){
							$(this).dialog("close");
						}
					}
				],
				open:function(event, ui){ $(".ui-dialog-titlebar-close").hide();}
			});
			$div.dialog('open');
		}else if ($(this).data('action')) {
			// メッセージなしのsubmit
	    	$('#outputInfo option').prop("selected",true);
			$(this).parents('form').attr('action', $(this).data('action'));
			$(this).parents('form').submit();
			if (ams.common.afterSubmit) {
				ams.common.afterSubmit();
			}
		}
	});


	/**
	 * 保存submit処理
	 * class属性にsubmitボタンが設定されている要素をクリックされた際にdata-action属性へ指定されたurlへform送信
	 */
	$("#save").on("click", function(e) {
		if ($("#changedDataFlg").val()) {
			// 確認メッセージ表示
			var $btn = $(this);
			var $div = $("<div id='_dialog'><span>保存します。<br />よろしいですか？</span></div>");

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
							if ($btn.data('action')) {
								$("#changedDataFlg").val("");
						    	$('#outputInfo option').prop("selected",true);
								$btn.parents('form').attr('action', $btn.data('action'));
								$btn.parents('form').submit();
							}
							$(this).dialog("close");
						}
					},
					{
						text: 'キャンセル' ,
						class: 'btn' ,
						click: function(){
							$(this).dialog("close");
						}
					}
				],
				open:function(event, ui){ $(".ui-dialog-titlebar-close").hide();}
			});
			$div.dialog('open');
		}else if ($(this).data('action')) {
			// メッセージなしのsubmit
	    	$('#outputInfo option').prop("selected",true);
			$(this).parents('form').attr('action', $(this).data('action'));
			$(this).parents('form').submit();
			if (ams.common.afterSubmit) {
				ams.common.afterSubmit();
			}
		}
	});

	$('input[name=right]').on('click', function() {
		// エラーメッセージクリア
		document.getElementById("MSTO0005M001").style.display="none";
		document.getElementById("MSTO0005M002").style.display="none";
		document.getElementById("MSTO0005M003").style.display="none";
    	if($('select[name=sourceInfo] option:selected').length == 0){
    		// チェックされていない場合、エラーメッセージ表示
    		document.getElementById("MSTO0005M001").style.display="block";
    		window.scrollTo( 0, 0 ) ;
    	}
    	leaveMove('sourceInfo', 'outputInfo');
	    // データ変更をマーク
		$("#changedDataFlg").val("1");
		$("#changedDataRedrawFlg").val("1");
    });

    $('input[name=left]').on('click', function() {
		// エラーメッセージクリア
		document.getElementById("MSTO0005M001").style.display="none";
		document.getElementById("MSTO0005M002").style.display="none";
		document.getElementById("MSTO0005M003").style.display="none";
    	if($('select[name=outputInfo] option:selected').length == 0){
    		// チェックされていない場合、エラーメッセージ表示
    		document.getElementById("MSTO0005M002").style.display="block";
    		window.scrollTo( 0, 0 ) ;
    	}
    	move('outputInfo', 'sourceInfo');
    	// データ変更をマーク
		$("#changedDataFlg").val("1");
		$("#changedDataRedrawFlg").val("1");
    });

    $('input[name=allRight]').on('click', function() {
		// エラーメッセージクリア
		document.getElementById("MSTO0005M001").style.display="none";
		document.getElementById("MSTO0005M002").style.display="none";
		document.getElementById("MSTO0005M003").style.display="none";
		leaveAllMove('sourceInfo', 'outputInfo');
    	// データ変更をマーク
		$("#changedDataFlg").val("1");
		$("#changedDataRedrawFlg").val("1");
    });

    $('input[name=allLeft]').on('click', function() {
		// エラーメッセージクリア
		document.getElementById("MSTO0005M001").style.display="none";
		document.getElementById("MSTO0005M002").style.display="none";
		document.getElementById("MSTO0005M003").style.display="none";
    	allMove('outputInfo', 'sourceInfo');
    	// データ変更をマーク
		$("#changedDataFlg").val("1");
		$("#changedDataRedrawFlg").val("1");
    });

    $('#testRun').on('click', function() {
    	$('#outputInfo option').prop("selected",true);
		$(this).parents('form').attr('action', $(this).data('action'));
		$(this).parents('form').submit();
    });

	//上段への並び替えボタン押下
	$("#btn_up").on("click", function() {
		// エラーメッセージクリア
		document.getElementById("MSTO0005M001").style.display="none";
		document.getElementById("MSTO0005M002").style.display="none";
		document.getElementById("MSTO0005M003").style.display="none";
    	if($('select[name=outputInfo] option:selected').length == 0){
    		// チェックされていない場合、エラーメッセージ表示
    		document.getElementById("MSTO0005M003").style.display="block";
    		window.scrollTo( 0, 0 ) ;
    	}
		$('select[name=outputInfo] option:selected').each(function() {
			//一つ上のレコードと並び替える
			var prev = $(this).prev("option");
			if (prev.length > 0) {
				$(this).insertBefore(prev);
			} else {
				return false;
			}
		});
		// データ変更をマーク
		$("#changedDataFlg").val("1");
		$("#changedDataRedrawFlg").val("1");
		$('select[name=outputInfo]').trigger('focus').trigger('blur');
	});

	//下段への並び替えボタン押下
	$("#btn_down").on("click", function() {
		// エラーメッセージクリア
		document.getElementById("MSTO0005M001").style.display="none";
		document.getElementById("MSTO0005M002").style.display="none";
		document.getElementById("MSTO0005M003").style.display="none";
    	if($('select[name=outputInfo] option:selected').length == 0){
    		// チェックされていない場合、エラーメッセージ表示
    		document.getElementById("MSTO0005M003").style.display="block";
    		window.scrollTo( 0, 0 ) ;
    	}
		$($('select[name=outputInfo] option:selected').get().reverse()).each(function() {
			//一つ上のレコードと並び替える
			var next = $(this).next("option");
			if (next.length > 0) {
				$(this).insertAfter(next);
			} else {
				return false;
			}
		});
		// データ変更をマーク
		$("#changedDataFlg").val("1");
		$("#changedDataRedrawFlg").val("1");
		$('select[name=outputInfo]').trigger('focus').trigger('blur');
	});

	// SQL編集欄変更時
	$("#SQLText").on("change", function() {
		// データ変更をマーク
		$("#changedDataOutSqlFlg").val("1");
	});


	// テキスト変更時
	$("input[type='text'],input[type='radio'],input[type='checkbox'],select").on("change", function() {
		// データ変更をマーク
		$("#changedDataFlg").val("1");
	});

    var move = function(_this, target) {
        $('select[name=' + _this + '] option:selected').each(function() {
            $(this).remove();
        });
    };

    var leaveMove = function(_this, target) {
        $('select[name=' + _this + '] option:selected').each(function() {
            $('select[name=' + target + ']').append($(this).clone());
        });
    };

    var allMove = function(_this, target) {
        $('select[name=' + _this + '] option').each(function() {
            $(this).remove();
        });
    };

    var leaveAllMove = function(_this, target) {
        $('select[name=' + _this + '] option').each(function() {
            $('select[name=' + target + ']').append($(this).clone());
        });
    };

	$("#btn_logout, #return_menu_botton").on("click", function(e) {
		if ($("#changedDataFlg").val()) {
			var that = this;
			var $div = $('<div id="_dialogLeave"><span>保存されていないため、入力した内容が破棄されますが宜しいでしょうか</span></div>');
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
							$("#changedDataFlg").val("");
							$(this).dialog("close");
							window.location.href = $(that).attr("href");
						}
					},
					{
						text: 'キャンセル' ,
						class: 'btn' ,
						click: function(){
							$(this).dialog("close");
						}
					}
				],
				open:function(event, ui){ $(".ui-dialog-titlebar-close").hide();}
			});
			$div.dialog('open');
		}
	});
});
