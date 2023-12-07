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

namespace('axio.common');

axio.common.preSubmit = function(that) {
	return true;
}
axio.common.afterSubmit = function() {}

$(function() {
	/**
	 * 共通submit処理
	 * class属性にsubmitボタンが設定されている要素をクリックされた際にdata-action属性へ指定されたurlへform送信
	 */
	$(".submit").on("click", function() {
		var that = this;
		if (axio.common.preSubmit) {
			if (axio.common.preSubmit(that)) {
				var existsProhibitedChar = false;
				if( !$(this).data('ignore-prohibited-char') ){
					// 禁則文字列入力チェック
					$("input[type='text'],textarea").each(function(index, element) {
						var el = $(element);
						if (!el.data('ignore-prohibited-char')) {
							if ( !el.attr("readonly") ) {
								if ( !el.attr("disabled") ) {
									el.removeClass("axio_field_error");
									var val = el.val();
									if (val) {
										if (val.match(/[<>"“'‘&\-%％_＿]/gi)) {
											el.addClass("axio_field_error");
											existsProhibitedChar = true;
										}
									}
								}
							}
						}
					});
				}

				if (existsProhibitedChar ) {
					if ($("ul.alert_prohibited_char").length) {
						$("ul.alert_prohibited_char").remove();
					}
					$("li.prohibited_char_li").remove();
					if ( $('ul.asm_alert').length ) {
						$('ul.asm_alert').append("<li class='prohibited_char_li'>入力禁止文字が入力されています。(禁止文字:<>\"“'‘&\-%％_＿)</li>");
					} else {
						$("<ul class='col-xs-12 alert alert-danger asm_alert asm_alert alert_prohibited_char' role='alert'><li class='prohibited_char_li'>入力禁止文字が入力されています。(禁止文字:<>\"“'‘&\-%％_＿)</li></ul>").prependTo('#content');
					}
					return;
				}
				if($(this).data('button')){
					// 確認メッセージ表示
					var $btn = $(this);
					var msg = $(this).data('button');
					var $div = $("<div id='_dialog'><span>" + msg + "します。<br />よろしいですか？</span></div>");

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
										$btn.parents('form').attr('action', $btn.data('action'));
										$btn.parents('form').submit();
										if (axio.common.afterSubmit) {
											axio.common.afterSubmit();
										}
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
					if (axio.common.afterSubmit) {
						axio.common.afterSubmit();
					}
				}
			}
		}
	});

	/**
	 * 完了メッセージダイアログの表示
	 */
	if($("#axioMessageDialog").length){
		$("#axioMessageDialog").dialog({
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
				$('#axioMessageDialog').remove();
			}
		});
	}

	$("#btn_window_close").ready(function(){
        var userAgent = window.navigator.userAgent.toLowerCase();
        if (userAgent.indexOf('msie') == -1 && userAgent.indexOf('trident') == -1) {
            $("#btn_window_close").hide();
        }
	  });

	/** 閉じるボタン */
	$("#btn_window_close").on('click', function(e) {
		var userAgent = window.navigator.userAgent.toLowerCase();
		if (userAgent.indexOf('msie') != -1 || userAgent.indexOf('trident') != -1) {
			window.open('about:blank','_self').close();
		}
	});
});
