
$(function() {


	// 選択された分類コード名称の分類コードIDを設定する。
	$("#selectClassCode").change(function(e){
       if ($("#editFlg").val() == "1") {
            var dispMode = "search";
            GpuMasterSetConfirm(e,dispMode);
        }else{
            var classCodeId = $(this).val();
            var selectClassName = $(this).find("option:selected").text();
            $("#classCodeId").val(classCodeId);
            $("#selectClassName").val(selectClassName);
            searchGpuMasterSet();
        }

	});

	// 検索条件のクリアボタンを押下時、相関チェックを行い処理を中断、または初期表示状態にする。
	$("#clearSearch").click(function(e){
         $("#codevalueName").show();
		if ($("#editFlg").val() == "1") {
			var dispMode = "init";
			GpuMasterSetConfirm(e,dispMode);
		}else{
			initGpuMasterSet();
		}
	});

    // 選択された分類によてリスト一覧を設定する。
    $("#classCodeValue").change(function(e){
        if ($("#editFlg").val() == "1") {
            var dispMode = "select";
            GpuMasterSetConfirm(e,dispMode);
        }else{
            var selectClassCodeValue = $(this).val();
            var selectClassCodeName = $(this).find("option:selected").text();
            $("#selectClassCodeValue").val(selectClassCodeValue);
            $("#selectClassCodeName").val( selectClassCodeName);
            selectGpuMasterSet();
        }

    });

	// 値選択一覧のコードリスト：単一選択処理
	$('input[id^=classCodeCheck]').change(function(){
		if ($(this).prop('checked')){
            // 一旦全てをクリアして再チェックする
            $('input[id^=classCodeCheck]').prop('checked', false);
            $(this).prop('checked', true);
            var checkIndex = $('input[id^=classCodeCheck]:checked').data("index");

            $("#classCodeNo").val($("#classCodeValue_" + checkIndex).text());
            $("#classCodeName").val($("#gpCodeMstName_" + checkIndex).text());
            $("#classCodeDetail").val($("#codeDetail_" + checkIndex).text());
            $("#classCodeOrder").val($("#dispOrder_" + checkIndex).text());
            //$("#classCodeNo").prop("disabled",true);
            $("#classCodeNo").attr('readonly',true);
        } else {
            $("#classCodeNo").val($("").text());
            $("#classCodeName").val($("").text());
            $("#classCodeDetail").val($("").text());
            $("#classCodeOrder").val($("").text());
            //$("#classCodeNo").prop("disabled", false);
            $("#classCodeNo").attr('readonly',false);
        }
	});


	// 値選択一覧の削除ボタン押下時処理
	$("#deletebutton").click(function(){
		var checkIndex = $('input[id^=classCodeCheck]:checked').data("index");
		document.getElementById("MSTO0001M001").style.display="none";
		//チェックされていない場合
		if(!checkIndex && checkIndex != 0){
			document.getElementById("MSTO0001M001").style.display="block";
			window.scrollTo( 0, 0 );
			return false;
		}
       var $div = $("<div id='_dialogLeave'><span> 選択した内容が削除されます。<br />よろしいですか？</span></div>");
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
		$('form').attr('action','./GpuMasterSetDelete');
        $('form').submit();
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
	});

	// テキスト変更時
	$("input[type='text'],input[type='radio'],input[type='checkbox'],select").on("change", function() {
		// データ変更をマーク
		$("#changedDataFlg").val("1");
	});




	// 初期表示状態に戻す。
	function initGpuMasterSet(){
		$("#changedDataFlg").val("");
		$('form').attr('action','./GpuMasterSet');
        $('form').submit();
	}

	// 検索でサブミット
	function searchGpuMasterSet(){
        var classCodeId = $("#classCodeId").val()
		$('form').attr('action','./GpuMasterSetSearch');
        $('form').submit();
	}
    function selectGpuMasterSet(){
        $('form').attr('action','./GpuMasterSetSelect');
        $('form').submit();
    }

	function GpuMasterSetConfirm(e,dispMode){
		if ($("#editFlg").val() == "1") {
			var that = this;
			var $div = $("<div id='_dialogLeave'><span>変更内容が保存されていません。<br />保存を行わない場合、変更内容は破棄されます。<br />よろしいですか？</span></div>");
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
							$("#editFlg").val("");
							$(this).dialog("close");
							switch(dispMode){
							case "init":
								initGpuMasterSet();
								break;
							case "search":
                                var classCodeId = $("#selectClassCode").val();
                                var selectClassName = $("#selectClassCode").find("option:selected").text();
                                $("#classCodeId").val(classCodeId);
                                $("#selectClassName").val(selectClassName);
								searchGpuMasterSet();
								break;
							case "select":
                                var selectClassCodeValue = $("#classCodeValue").val();
                                var selectClassCodeName = $("#classCodeValue").find("option:selected").text()
                                $("#selectClassCodeValue").val(selectClassCodeValue);
                                $("#selectClassCodeName").val( selectClassCodeName);
								selectGpuMasterSet();
								break;
							default:
								break;
							}
						}
					},
					{
						text: 'キャンセル' ,
						class: 'btn' ,
						click: function(){
                            switch(dispMode){
                            case "search":
                                $("#selectClassCode").val($("#classCodeId").val());
                                break;
                            case "select":
                                $("#classCodeValue").val($("#selectClassCodeValue").val());
                                break;
                            default:
                                break;
                            }
							$(this).dialog("close");
						}
					}
				],
				open:function(event, ui){ $(".ui-dialog-titlebar-close").hide();}
			});
			$div.dialog('open');
		}
	}
	function selectGpuMasterSetConfirm(e,index){
		if ($("#editFlg").val() == "1") {
			var that = this;
			var $div = $("<div id='_dialogLeave'><span>変更内容が保存されていません。<br />保存を行わない場合、変更内容は破棄されます。<br />よろしいですか？</span></div>");
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
							$("#editFlg").val("");
							$(this).dialog("close");
							selectGpuMasterSet();
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
	}

	$("#btn_logout").on("click", function(e) {
		if ($("#changedDataFlg").val()) {
			var that = this;
			var $div = $("<div id='_dialogLeave'><span>保存されていないため、入力した内容が破棄されますが宜しいでしょうか</span></div>");
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