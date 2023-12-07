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

namespace('axio.mgpCsvExport');

$(function() {
	/**
	 * 再描画submit処理
	 * class属性にsubmitボタンが設定されている要素をクリックされた際にdata-action属性へ指定されたurlへform送信
	 */


      var table = $('#sourceInfo-table').DataTable({
          lengthChange: true, // 件数切替機能 無効
          searching: false,   // 検索機能 無効
          ordering: false, // ソート機能 有効
          info: false,    // 情報表示 無効
          paging: false,  // ページング機能 無効
          scrollY: '402px',   // 縦スクロールバーを有効にする (scrollYは200, "200px"など「最大の高さ」を指定します)
          scrollX: '100%',
          autoWidth:false,     // 列幅の自動計算 無効
          destroy: true,
          columns:[
              {"width":"15%"}, //  No
              {"width":"0%"}, //   カラム物理名
              {"width":"85%"}, //  表示順
              ]
      });

      var table = $('#sourceOut-table').DataTable({
          lengthChange: true, // 件数切替機能 無効
          searching: false,   // 検索機能 無効
          ordering: false, // ソート機能 有効
          info: false,    // 情報表示 無効
          paging: false,  // ページング機能 無効
          scrollY: '402px',   // 縦スクロールバーを有効にする (scrollYは200, "200px"など「最大の高さ」を指定します)
          scrollX: false,
          autoWidth:false,     // 列幅の自動計算 無効
          destroy: true,
          columns:[
              {"width":"15%"}, //  No
              {"width":"0%"}, //   カラム物理名
              {"width":"85%"}, //  カラム論理名
              ]
      });

      $('#sourceInfo tr td.dataTables_empty').remove();
      $('#outputInfo tr td.dataTables_empty').remove();

    var targetSAddClass = function(target) {

      $(target).on( 'click', 'tr', function () {
      if ( $(this).hasClass('selected') ) {
          $(this).removeClass('selected');
      }
      else {
          var trs = $(this).parent().find('tr');
          trs.removeClass('selected');
          $(this).addClass('selected');
      }
     } );
    };
	$("#clear").on("click", function() {
		if($("#changedDataRedrawFlg").val()){
			// 確認メッセージ表示
			var $btn = $(this);
			var $div = $('<div id="_dialogLeave"><span>登録されていないため、入力した内容が破棄されますが宜しいでしょうか</span></div>');

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
                                sqlDataGet();
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
            sqlDataGet();
			$(this).parents('form').attr('action', $(this).data('action'));
			$(this).parents('form').submit();
		}
	});

    // CSVファイル情報選択された場合
    $("#selectClassCode").change(function(e){
        if($("#changedDataFlg").val()){
            // 確認メッセージ表示
            var $btn = $(this);
            var $div = $('<div id="_dialogLeave"><span>登録されていないため、入力した内容が破棄されますが宜しいでしょうか</span></div>');

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
                            $("#selectClassCodeBak").val($("#selectClassCode").val());
                            $(this).dialog("close");
                            selectCsvFiledata();

                        }
                    },
                    {
                        text: 'キャンセル' ,
                        class: 'btn' ,
                        click: function(){
                            $("#selectClassCode").val($("#selectClassCodeBak").val());
                            $(this).dialog("close");
                        }
                    }
                ],
                open:function(event, ui){ $(".ui-dialog-titlebar-close").hide();}
            });
            $div.dialog('open');
        }else {
             $("#selectClassCodeBak").val($("#selectClassCode").val());
             selectCsvFiledata();
        }
    });

    // 選択された分類コード名称の分類コードIDを設定する。
    $("#sqlOutTableName").change(function(e){
        if($("#changedDataRedrawFlg").val()){
            // 確認メッセージ表示
            var $btn = $(this);
            var $div = $('<div id="_dialogLeave"><span>登録されていないため、入力した内容が破棄されますが宜しいでしょうか</span></div>');

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
                           $(this).dialog("close");
                            $("#sqlOutTableNameBak").val($("#sqlOutTableName").val());
                           searchOutTableSet();
                        }
                    },
                    {
                        text: 'キャンセル' ,
                        class: 'btn' ,
                        click: function(){
                            $("#sqlOutTableName").val($("#sqlOutTableNameBak").val());
                            $(this).dialog("close");
                        }
                    }
                ],
                open:function(event, ui){ $(".ui-dialog-titlebar-close").hide();}
            });
            $div.dialog('open');
        }else  {
            $("#sqlOutTableNameBak").val($("#sqlOutTableName").val());
            searchOutTableSet();
        }
    });

    function selectCsvFiledata(){
        $('form').attr('action','./mgpCsvExportSelectCsvFiledata');
        $('form').submit();
    }
    // 検索でajax
    function searchOutTableSet(){

         $.ajax({
                 url:"./mgpCsvExport/redraw",
                 dataType:"json",
                 type:"post",
                 async:"true",
                 data:{sqlOutTableName:$("#sqlOutTableName").val()},
                 success: function(data){
                    var targetViewInfoList = data.targetViewInfoList;
                    $('#sourceInfo').empty();
                    $('#outputInfo').empty();
//                    $("<tr class='odd'><td valign='top' colspan='2' class='dataTables_empty ' >" + "対象データはありません" + "</td></tr>").appendTo($('#outputInfo'));

                    var sqlInputDataTxt ="";
                    for(var i = 0;i<targetViewInfoList.length;i++){
                        sqlInputDataTxt = sqlInputDataTxt + targetViewInfoList[i].dirNo + " " + targetViewInfoList[i].columnPhysicalName + " " + targetViewInfoList[i].columnLogicalName + "<br>"
                    $("<tr><td th:id=" + 'dirNo_' + i +  "  >"  +  targetViewInfoList[i].dirNo
                    + "</td><td style='display:none' th:id="  + 'columnPhysicalName_' + i  +  " class='text-left ' >" + targetViewInfoList[i].columnPhysicalName
                    + "</td><td th:id="  + 'columnLogicalName_' + i   +  " class='text-left ' >" + targetViewInfoList[i].columnLogicalName + "</td></tr>").appendTo($('#sourceInfo'));
                    }
                    if (sqlInputDataTxt ===""){
                        $("#changedDataRedrawFlg").val("");
                    }
                    $('#sqlInputDataTxt').val(sqlInputDataTxt);


                },
                error: function(err){
    				console.log(err);
                }
        });
    }


	/**
	 * 登録submit処理
	 * class属性にsubmitボタンが設定されている要素をクリックされた際にdata-action属性へ指定されたurlへform送信
	 */
	$("#save").on("click", function(e) {

		//DB登録／更新ボタン連打防止,処理完了まで押下不可
		$(this).prop("disabled", true);

        sqlDataGet();
		if ($("#changedDataFlg").val()) {
			// 確認メッセージ表示
			var $btn = $(this);
			var $div = $("<div id='_dialog'><span>登録します。<br />よろしいですか？</span></div>");

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

							//DB登録／更新ボタン連打防止,処理完、押下可
							$(this).prop("disabled", false);
						}
					},
					{
						text: 'キャンセル' ,
						class: 'btn' ,
						click: function(){
							$(this).dialog("close");

							//DB登録／更新ボタン連打防止,処理完、押下可
							$(this).prop("disabled", false);
						}
					}
				],
				open:function(event, ui){ $(".ui-dialog-titlebar-close").hide();}
			});
			$div.dialog('open');
		} else if ($(this).data('action')) {
			// メッセージなしのsubmit
			$(this).parents('form').attr('action', $(this).data('action'));
			$(this).parents('form').submit();
			if (axio.common.afterSubmit) {
				axio.common.afterSubmit();
			}
			//DB登録／更新ボタン連打防止,処理完、押下可
			$(this).prop("disabled", false);
		}
	});

	$('input[name=right]').on('click', function() {
		// エラーメッセージクリア
		document.getElementById("MSTO0005M001").style.display="none";
		document.getElementById("MSTO0005M002").style.display="none";
		document.getElementById("MSTO0005M003").style.display="none";
    	if($('#sourceInfo tr.selected').length == 0){
    		// チェックされていない場合、エラーメッセージ表示
    		document.getElementById("MSTO0005M001").style.display="block";
    		window.scrollTo( 0, 0 ) ;
    	}
    	leaveMove('#sourceInfo', '#outputInfo');
	    // データ変更をマーク
		$("#changedDataFlg").val("1");
		$("#changedDataRedrawFlg").val("1");
		//Save button active
		$("#save").prop("disabled", false);
    });

    $('input[name=left]').on('click', function() {
		// エラーメッセージクリア
		document.getElementById("MSTO0005M001").style.display="none";
		document.getElementById("MSTO0005M002").style.display="none";
		document.getElementById("MSTO0005M003").style.display="none";
    	if($('#outputInfo tr.selected').length == 0){
    		// チェックされていない場合、エラーメッセージ表示
    		document.getElementById("MSTO0005M002").style.display="block";
    		window.scrollTo( 0, 0 ) ;
    	}
    	move('outputInfo', 'sourceInfo');
    	// データ変更をマーク
		$("#changedDataFlg").val("1");
		$("#changedDataRedrawFlg").val("1");
		//Save button active
		$("#save").prop("disabled", false);
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
		//Save button active
		$("#save").prop("disabled", false);
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
		//Save button active
		$("#save").prop("disabled", false);
    });

    $('#sqlInputLink').on('click', function() {
        var data=$("#sqlInputDataTxt").val();
        if (data=="" || data =="undefined" || data==null){
            data = "出力対象が選択されていないため、出力対象を選択してください。"
        }
        var $div = $('<div id="_dialogLeave"><span>'+ data  +'</span></div>');
            $div.dialog({
                title: '抽出元情報一覧',
                modal:true,
                autoOpen: false,
                modal: true,
                width: 500,
                buttons: [
                    {
                        text: 'OK' ,
                        class: 'btn'  ,
                        click: function(){
                            $(this).dialog("close");
                        }
                    }
                ],
                open:function(event, ui){ $(".ui-dialog-titlebar-close").hide();}
            });
            $div.dialog('open');
    });

    // SQLチェックsubmit処理
    $('#sqlCheck').on('click', function() {

    	sqlDataGet();

    	$(this).parents('form').attr('action', $(this).data('action'));
    	$(this).parents('form').submit();

    });

	//上段への並び替えボタン押下
	$("#btn_up").on("click", function() {
		// エラーメッセージクリア
		document.getElementById("MSTO0005M001").style.display="none";
		document.getElementById("MSTO0005M002").style.display="none";
		document.getElementById("MSTO0005M003").style.display="none";
    	if($('#outputInfo tr.selected').length == 0){
    		// チェックされていない場合、エラーメッセージ表示
    		document.getElementById("MSTO0005M003").style.display="block";
    		window.scrollTo( 0, 0 ) ;
    	}
		$('#outputInfo tr.selected').each(function() {
            var index = $(this).index();
			//一つ上のレコードと並び替える
			var prev = $(this).prev("tr");
			if (prev.length > 0) {
                $(this).find("td").eq(0).text(index);
				$(this).insertBefore(prev);
                prev.find("td").eq(0).text(index +1);
			} else {
				return false;
			}
		});
		// データ変更をマーク
		$("#changedDataFlg").val("1");
		$("#changedDataRedrawFlg").val("1");
		//Save button active
		$("#save").prop("disabled", false);
		$('select[name=outputInfo]').trigger('focus').trigger('blur');
	});

	//下段への並び替えボタン押下
	$("#btn_down").on("click", function() {
		// エラーメッセージクリア
		document.getElementById("MSTO0005M001").style.display="none";
		document.getElementById("MSTO0005M002").style.display="none";
		document.getElementById("MSTO0005M003").style.display="none";
    	if($('#outputInfo tr.selected').length == 0){
    		// チェックされていない場合、エラーメッセージ表示
    		document.getElementById("MSTO0005M003").style.display="block";
    		window.scrollTo( 0, 0 ) ;
    	}
		$($('#outputInfo tr.selected').get().reverse()).each(function() {
			//一つ上のレコードと並び替える
            var index = $(this).index();
			var next = $(this).next("tr");
			if (next.length > 0) {
				$(this).insertAfter(next);
                next.find("td").eq(0).text(index + 1);
                $(this).find("td").eq(0).text(index +2);
			} else {
				return false;
			}
		});
		// データ変更をマーク
		$("#changedDataFlg").val("1");
		$("#changedDataRedrawFlg").val("1");
		//Save button active
		$("#save").prop("disabled", false);
		$('select[name=outputInfo]').trigger('focus').trigger('blur');
	});

	// SQL編集欄変更時
	$("#sqlWhereDef").on("change", function() {
		// データ変更をマーク
		$("#changedDataSqlWhereDefFlg").val("1");
		$("#changedDataFlg").val("1");
		//Save button active
		$("#save").prop("disabled", false);
	});
    //
    targetSAddClass('#sourceInfo');
    targetSAddClass('#outputInfo');

	// テキスト変更時
	$("input[type='text'],input[type='radio'],input[type='checkbox'],select").on("change", function() {
		// データ変更をマーク
		$("#changedDataFlg").val("1");
		//Save button active
		$("#save").prop("disabled", false);
	});

    var move = function(_this, target) {
        var index=$('#outputInfo tr.selected').index();
        $('#outputInfo tr.selected').remove();
        var indexafter=0;
         $('#outputInfo tr').each(function() {
            indexafter= $(this).index();
            if(indexafter >= index) {
                $(this).find("td").eq(0).text(indexafter + 1);
            }
        });
    };

    var leaveMove = function(_this, target) {
//        $('#outputInfo tr.odd').remove();
        var i=$('#outputInfo tr').length +1;
         var td = $('#sourceInfo tr.selected').find("td");
            if ( td.length >= 3) {
             $("<tr><td th:id=" + 'outdirNo_' + i +  "  >"  +  i
                    + "</td><td style='display:none' th:id="  + 'outcolumnPhysicalName_' + i  +  " class='text-left ' >" + td.eq(1).text()
                    + "</td><td th:id="  + 'outcolumnLogicalName_' + i   +  " class='text-left ' >" + td.eq(2).text() + "</td></tr>").appendTo($('#outputInfo'));
            }
    };

    var allMove = function(_this, target) {
        $('#outputInfo tr').each(function() {
            $(this).remove();
//           $(this).appendTo($('#sourceInfo'));
        });
//        $("<tr class='odd'><td valign='top' colspan='2' class='dataTables_empty ' >" + "対象データはありません" + "</td></tr>").appendTo($('#outputInfo'));
    };

    var leaveAllMove = function(_this, target) {
        var i =$('#outputInfo tr').length +1;
        $('#sourceInfo tr').each(function() {
            var td = $(this).find("td");
            if ( td.length >= 3) {
              $("<tr><td th:id=" + 'outdirNo_' + i +  "  >"  +  i
                    + "</td><td style='display:none' th:id="  + 'outcolumnPhysicalName_' + i  +  " class='text-left ' >" + td.eq(1).text()
                    + "</td><td th:id="  + 'outcolumnLogicalName_' + i   +  " class='text-left ' >" + td.eq(2).text() + "</td></tr>").appendTo($('#outputInfo'));
            }
            i++;
        });
    };


    var sqlDataGet = function() {
        var dataInfoList =  new Array();
        var targetInfoView = {};
        var sqlInfoData ="";
         $('#sourceInfo tr').each(function() {
            var td = $(this).find("td");
            if (td.length >= 3) {
                for (var i = 0; i < td.length; i++) {
                    if (i <2 ){
                        sqlInfoData = sqlInfoData + td.eq(i).text() + ","
                    } else {
                        sqlInfoData = sqlInfoData + td.eq(i).text() + ";"
                    }
                }
            }

        });
        if (sqlInfoData.length > 0){
            sqlInfoData   = sqlInfoData.substring(0,sqlInfoData.length -1);
        }
        $("#sqlInfoData").val(sqlInfoData);

        var dataList =  new Array();
        var targetView = {};

        var  flag = false;
        var sqlOutData = "select ";
        var sqlColumnDef ="";
         $('#outputInfo tr').each(function() {
            var td = $(this).find("td");
            if (td.length >= 3) {
                 flag = true;
            }

            for (var i = 0; i < td.length; i++) {
                if(i===1){
                    sqlOutData =sqlOutData + td.eq(i).text() + ","
                    targetView.dirNo = td.eq(i - 1).text();
                    targetView.columnLogicalName = td.eq(i).text();
                    targetView.columnLogicalName = td.eq(i + 1).text();
                    dataList.push(targetView);
                }
                if (i <2 ){
                    sqlColumnDef = sqlColumnDef + td.eq(i).text() + ","
                } else {
                    sqlColumnDef = sqlColumnDef + td.eq(i).text() + ";"
                }
            }

        });
        if (flag) {
            sqlOutData = sqlOutData.substring(0,sqlOutData.length -1) + " from ";
            sqlOutData = sqlOutData + $("#sqlOutTableName").val() + " ";
            sqlOutData = sqlOutData + $("#sqlWhereDef").val();

            sqlColumnDef   = sqlColumnDef.substring(0,sqlColumnDef.length -1);
            $("#sqlColumnDef").val(sqlColumnDef);
            $("#sqlOutData").val(sqlOutData);
            $("#targetViewInfoList").val(dataList);
        } else {
            $("#sqlColumnDef").val("");
            $("#sqlOutData").val("");
        }

    };


	$("#btn_logout").on("click", function(e) {
		if ($("#changedDataFlg").val()) {
			var that = this;
			var $div = $('<div id="_dialogLeave"><span>登録されていないため、入力した内容が破棄されますが宜しいでしょうか</span></div>');
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
