/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

// Use IIFE to avoid leaking names to other scripts.
(function () {

function getTimeInMs() {
    return new Date().getTime();
}

class TimeLog {
    constructor() {
        this.start = getTimeInMs();
    }

    log(name) {
        let end = getTimeInMs();
        console.log(name, end - this.start, 'ms');
        this.start = end;
    }
}

class ProgressBar {
    constructor() {
        let str = `
            <div class="modal" tabindex="-1" role="dialog">
                <div class="modal-dialog" role="document">
                    <div class="modal-content">
                        <div class="modal-header"><h5 class="modal-title">Loading page...</h5></div>
                        <div class="modal-body">
                            <div class="progress">
                                <div class="progress-bar" role="progressbar"
                                    style="width: 0%" aria-valuenow="0" aria-valuemin="0"
                                    aria-valuemax="100">0%</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        this.modal = $(str).appendTo($('body'));
        this.progress = 0;
        this.shownCallback = null;
        this.modal.on('shown.bs.modal', () => this._onShown());
        // Shorten progress bar update time.
        this.modal.find('.progress-bar').css('transition-duration', '0ms');
        this.shown = false;
    }

    // progress is [0-100]. Return a Promise resolved when the update is shown.
    updateAsync(text, progress) {
        progress = parseInt(progress);  // Truncate float number to integer.
        return this.showAsync().then(() => {
            if (text) {
                this.modal.find('.modal-title').text(text);
            }
            this.progress = progress;
            this.modal.find('.progress-bar').css('width', progress + '%')
                    .attr('aria-valuenow', progress).text(progress + '%');
            // Leave 100ms for the progess bar to update.
            return createPromise((resolve) => setTimeout(resolve, 100));
        });
    }

    showAsync() {
        if (this.shown) {
            return createPromise();
        }
        return createPromise((resolve) => {
            this.shownCallback = resolve;
            this.modal.modal({
                show: true,
                keyboard: false,
                backdrop: false,
            });
        });
    }

    _onShown() {
        this.shown = true;
        if (this.shownCallback) {
            let callback = this.shownCallback;
            this.shownCallback = null;
            callback();
        }
    }

    hide() {
        this.shown = false;
        this.modal.modal('hide');
    }
}

function openHtml(name, attrs={}) {
    let s = `<${name} `;
    for (let key in attrs) {
        s += `${key}="${attrs[key]}" `;
    }
    s += '>';
    return s;
}

function closeHtml(name) {
    return `</${name}>`;
}

function getHtml(name, attrs={}) {
    let text;
    if ('text' in attrs) {
        text = attrs.text;
        delete attrs.text;
    }
    let s = openHtml(name, attrs);
    if (text) {
        s += text;
    }
    s += closeHtml(name);
    return s;
}

function getTableRow(cols, colName, attrs={}) {
    let s = openHtml('tr', attrs);
    for (let col of cols) {
        s += `<${colName}>${col}</${colName}>`;
    }
    s += '</tr>';
    return s;
}

function getProcessName(pid) {
    let name = gProcesses[pid];
    return name ? `${pid} (${name})`: pid.toString();
}

function getThreadName(tid) {
    let name = gThreads[tid];
    return name ? `${tid} (${name})`: tid.toString();
}

function getLibName(libId) {
    return gLibList[libId];
}

function getFuncName(funcId) {
    return gFunctionMap[funcId].f;
}

function getLibNameOfFunction(funcId) {
    return getLibName(gFunctionMap[funcId].l);
}

function getFuncSourceRange(funcId) {
    let func = gFunctionMap[funcId];
    if (func.hasOwnProperty('s')) {
        return {fileId: func.s[0], startLine: func.s[1], endLine: func.s[2]};
    }
    return null;
}

function getFuncDisassembly(funcId) {
    let func = gFunctionMap[funcId];
    return func.hasOwnProperty('d') ? func.d : null;
}

function getSourceFilePath(sourceFileId) {
    return gSourceFiles[sourceFileId].path;
}

function getSourceCode(sourceFileId) {
    return gSourceFiles[sourceFileId].code;
}

function isClockEvent(eventInfo) {
    return eventInfo.eventName.includes('task-clock') ||
            eventInfo.eventName.includes('cpu-clock');
}

let createId = function() {
    let currentId = 0;
    return () => `id${++currentId}`;
}();

class TabManager {
    constructor(divContainer) {
        let id = createId();
        divContainer.append(`<ul class="nav nav-pills mb-3 mt-3 ml-3" id="${id}" role="tablist">
            </ul><hr/><div class="tab-content" id="${id}Content"></div>`);
        this.ul = divContainer.find(`#${id}`);
        this.content = divContainer.find(`#${id}Content`);
        // Map from title to [tabObj, drawn=false|true].
        this.tabs = new Map();
        this.tabActiveCallback = null;
    }

    addTab(title, tabObj) {
        let id = createId();
        this.content.append(`<div class="tab-pane" id="${id}" role="tabpanel"
            aria-labelledby="${id}-tab"></div>`);
        this.ul.append(`
            <li class="nav-item">
                <a class="nav-link" id="${id}-tab" data-toggle="pill" href="#${id}" role="tab"
                    aria-controls="${id}" aria-selected="false">${title}</a>
            </li>`);
        tabObj.init(this.content.find(`#${id}`));
        this.tabs.set(title, [tabObj, false]);
        this.ul.find(`#${id}-tab`).on('shown.bs.tab', () => this.onTabActive(title));
        return tabObj;
    }

    setActiveAsync(title) {
        let tabObj = this.findTab(title);
        return createPromise((resolve) => {
            this.tabActiveCallback = resolve;
            let id = tabObj.div.attr('id') + '-tab';
            this.ul.find(`#${id}`).tab('show');
        });
    }

    onTabActive(title) {
        let array = this.tabs.get(title);
        let tabObj = array[0];
        let drawn = array[1];
        if (!drawn) {
            tabObj.draw();
            array[1] = true;
        }
        if (this.tabActiveCallback) {
            let callback = this.tabActiveCallback;
            this.tabActiveCallback = null;
            callback();
        }
    }

    findTab(title) {
        let array = this.tabs.get(title);
        return array ? array[0] : null;
    }
}

function createEventTabs(id) {
    let ul = `<ul class="nav nav-pills mb-3 mt-3 ml-3" id="${id}" role="tablist">`;
    let content = `<div class="tab-content" id="${id}Content">`;
    for (let i = 0; i < gSampleInfo.length; ++i) {
        let subId = id + '_' + i;
        let title = gSampleInfo[i].eventName;
        ul += `
            <li class="nav-item">
                <a class="nav-link" id="${subId}-tab" data-toggle="pill" href="#${subId}" role="tab"
                aria-controls="${subId}" aria-selected="${i == 0 ? "true" : "false"}">${title}</a>
            </li>`;
        content += `
            <div class="tab-pane" id="${subId}" role="tabpanel" aria-labelledby="${subId}-tab">
            </div>`;
    }
    ul += '</ul>';
    content += '</div>';
    return ul + content;
}

function createViewsForEvents(div, createViewCallback) {
    let views = [];
    if (gSampleInfo.length == 1) {
        views.push(createViewCallback(div, gSampleInfo[0]));
    } else if (gSampleInfo.length > 1) {
        // If more than one event, draw them in tabs.
        let id = createId();
        div.append(createEventTabs(id));
        for (let i = 0; i < gSampleInfo.length; ++i) {
            let subId = id + '_' + i;
            views.push(createViewCallback(div.find(`#${subId}`), gSampleInfo[i]));
        }
        div.find(`#${id}_0-tab`).tab('show');
    }
    return views;
}

// Return a promise to draw views.
function drawViewsAsync(views, totalProgress, drawViewCallback) {
    if (views.length == 0) {
        return createPromise();
    }
    let drawPos = 0;
    let eachProgress = totalProgress / views.length;
    function drawAsync() {
        if (drawPos == views.length) {
            return createPromise();
        }
        return drawViewCallback(views[drawPos++], eachProgress).then(drawAsync);
    }
    return drawAsync();
}

// Show global information retrieved from the record file, including:
//   record time
//   machine type
//   Android version
//   record cmdline
//   total samples
class RecordFileView {
    constructor(divContainer) {
        this.div = $('<div>');
        this.div.appendTo(divContainer);
    }

    draw() {
        google.charts.setOnLoadCallback(() => this.realDraw());
    }

    realDraw() {
        this.div.empty();
        // Draw a table of 'Name', 'Value'.
        let rows = [];
        if (gRecordInfo.recordTime) {
            rows.push(['Record Time', gRecordInfo.recordTime]);
        }
        if (gRecordInfo.machineType) {
            rows.push(['Machine Type', gRecordInfo.machineType]);
        }
        if (gRecordInfo.androidVersion) {
            rows.push(['Android Version', gRecordInfo.androidVersion]);
        }
        if (gRecordInfo.androidBuildFingerprint) {
            rows.push(['Build Fingerprint', gRecordInfo.androidBuildFingerprint]);
        }
        if (gRecordInfo.kernelVersion) {
            rows.push(['Kernel Version', gRecordInfo.kernelVersion]);
        }
        if (gRecordInfo.recordCmdline) {
            rows.push(['Record cmdline', gRecordInfo.recordCmdline]);
        }
        rows.push(['Total Samples', '' + gRecordInfo.totalSamples]);

        let data = new google.visualization.DataTable();
        data.addColumn('string', '');
        data.addColumn('string', '');
        data.addRows(rows);
        for (let i = 0; i < rows.length; ++i) {
            data.setProperty(i, 0, 'className', 'boldTableCell');
        }
        let table = new google.visualization.Table(this.div.get(0));
        table.draw(data, {
            width: '100%',
            sort: 'disable',
            allowHtml: true,
            cssClassNames: {
                'tableCell': 'tableCell',
            },
        });
    }
}

// Show pieChart of event count percentage of each process, thread, library and function.
class ChartView {
    constructor(divContainer, eventInfo) {
        this.div = $('<div>').appendTo(divContainer);
        this.eventInfo = eventInfo;
        this.processInfo = null;
        this.threadInfo = null;
        this.libInfo = null;
        this.states = {
            SHOW_EVENT_INFO: 1,
            SHOW_PROCESS_INFO: 2,
            SHOW_THREAD_INFO: 3,
            SHOW_LIB_INFO: 4,
        };
        if (isClockEvent(this.eventInfo)) {
            this.getSampleWeight = function (eventCount) {
                return (eventCount / 1000000.0).toFixed(3).toLocaleString() + ' ms';
            };
        } else {
            this.getSampleWeight = (eventCount) => eventCount.toLocaleString();
        }
    }

    _getState() {
        if (this.libInfo) {
            return this.states.SHOW_LIB_INFO;
        }
        if (this.threadInfo) {
            return this.states.SHOW_THREAD_INFO;
        }
        if (this.processInfo) {
            return this.states.SHOW_PROCESS_INFO;
        }
        return this.states.SHOW_EVENT_INFO;
    }

    _goBack() {
        let state = this._getState();
        if (state == this.states.SHOW_PROCESS_INFO) {
            this.processInfo = null;
        } else if (state == this.states.SHOW_THREAD_INFO) {
            this.threadInfo = null;
        } else if (state == this.states.SHOW_LIB_INFO) {
            this.libInfo = null;
        }
        this.draw();
    }

    _selectHandler(chart) {
        let selectedItem = chart.getSelection()[0];
        if (selectedItem) {
            let state = this._getState();
            if (state == this.states.SHOW_EVENT_INFO) {
                this.processInfo = this.eventInfo.processes[selectedItem.row];
            } else if (state == this.states.SHOW_PROCESS_INFO) {
                this.threadInfo = this.processInfo.threads[selectedItem.row];
            } else if (state == this.states.SHOW_THREAD_INFO) {
                this.libInfo = this.threadInfo.libs[selectedItem.row];
            }
            this.draw();
        }
    }

    draw() {
        google.charts.setOnLoadCallback(() => this.realDraw());
    }

    realDraw() {
        this.div.empty();
        this._drawTitle();
        this._drawPieChart();
    }

    _drawTitle() {
        // Draw a table of 'Name', 'Event Count'.
        let rows = [];
        rows.push(['Event Type: ' + this.eventInfo.eventName,
                   this.getSampleWeight(this.eventInfo.eventCount)]);
        if (this.processInfo) {
            rows.push(['Process: ' + getProcessName(this.processInfo.pid),
                       this.getSampleWeight(this.processInfo.eventCount)]);
        }
        if (this.threadInfo) {
            rows.push(['Thread: ' + getThreadName(this.threadInfo.tid),
                       this.getSampleWeight(this.threadInfo.eventCount)]);
        }
        if (this.libInfo) {
            rows.push(['Library: ' + getLibName(this.libInfo.libId),
                       this.getSampleWeight(this.libInfo.eventCount)]);
        }
        let data = new google.visualization.DataTable();
        data.addColumn('string', '');
        data.addColumn('string', '');
        data.addRows(rows);
        for (let i = 0; i < rows.length; ++i) {
            data.setProperty(i, 0, 'className', 'boldTableCell');
        }
        let wrapperDiv = $('<div>');
        wrapperDiv.appendTo(this.div);
        let table = new google.visualization.Table(wrapperDiv.get(0));
        table.draw(data, {
            width: '100%',
            sort: 'disable',
            allowHtml: true,
            cssClassNames: {
                'tableCell': 'tableCell',
            },
        });
        if (this._getState() != this.states.SHOW_EVENT_INFO) {
            $('<button type="button" class="btn btn-primary">Back</button>').appendTo(this.div)
                .click(() => this._goBack());
        }
    }

    _drawPieChart() {
        let state = this._getState();
        let title = null;
        let firstColumn = null;
        let rows = [];
        let thisObj = this;
        function getItem(name, eventCount, totalEventCount) {
            let sampleWeight = thisObj.getSampleWeight(eventCount);
            let percent = (eventCount * 100.0 / totalEventCount).toFixed(2) + '%';
            return [name, eventCount, getHtml('pre', {text: name}) +
                        getHtml('b', {text: `${sampleWeight} (${percent})`})];
        }

        if (state == this.states.SHOW_EVENT_INFO) {
            title = 'Processes in event type ' + this.eventInfo.eventName;
            firstColumn = 'Process';
            for (let process of this.eventInfo.processes) {
                rows.push(getItem('Process: ' + getProcessName(process.pid), process.eventCount,
                                  this.eventInfo.eventCount));
            }
        } else if (state == this.states.SHOW_PROCESS_INFO) {
            title = 'Threads in process ' + getProcessName(this.processInfo.pid);
            firstColumn = 'Thread';
            for (let thread of this.processInfo.threads) {
                rows.push(getItem('Thread: ' + getThreadName(thread.tid), thread.eventCount,
                                  this.processInfo.eventCount));
            }
        } else if (state == this.states.SHOW_THREAD_INFO) {
            title = 'Libraries in thread ' + getThreadName(this.threadInfo.tid);
            firstColumn = 'Library';
            for (let lib of this.threadInfo.libs) {
                rows.push(getItem('Library: ' + getLibName(lib.libId), lib.eventCount,
                                  this.threadInfo.eventCount));
            }
        } else if (state == this.states.SHOW_LIB_INFO) {
            title = 'Functions in library ' + getLibName(this.libInfo.libId);
            firstColumn = 'Function';
            for (let func of this.libInfo.functions) {
                rows.push(getItem('Function: ' + getFuncName(func.f), func.c[1],
                                  this.libInfo.eventCount));
            }
        }
        let data = new google.visualization.DataTable();
        data.addColumn('string', firstColumn);
        data.addColumn('number', 'EventCount');
        data.addColumn({type: 'string', role: 'tooltip', p: {html: true}});
        data.addRows(rows);

        let wrapperDiv = $('<div>');
        wrapperDiv.appendTo(this.div);
        let chart = new google.visualization.PieChart(wrapperDiv.get(0));
        chart.draw(data, {
            title: title,
            width: 1000,
            height: 600,
            tooltip: {isHtml: true},
        });
        google.visualization.events.addListener(chart, 'select', () => this._selectHandler(chart));
    }
}


class ChartStatTab {
    init(div) {
        this.div = div;
    }

    draw() {
        new RecordFileView(this.div).draw();
        let views = createViewsForEvents(this.div, (div, eventInfo) => {
            return new ChartView(div, eventInfo);
        });
        for (let view of views) {
            view.draw();
        }
    }
}


class SampleTableTab {
    init(div) {
        this.div = div;
    }

    draw() {
        let views = [];
        createPromise()
            .then(updateProgress('Draw SampleTable...', 0))
            .then(wait(() => {
                this.div.empty();
                views = createViewsForEvents(this.div, (div, eventInfo) => {
                    return new SampleTableView(div, eventInfo);
                });
            }))
            .then(() => drawViewsAsync(views, 100, (view, progress) => view.drawAsync(progress)))
            .then(hideProgress());
    }
}

// Select the way to show sample weight in SampleTableTab.
// 1. Show percentage of event count.
// 2. Show event count (For cpu-clock and task-clock events, it is time in ms).
class SampleTableWeightSelectorView {
    constructor(divContainer, eventInfo, onSelectChange) {
        let options = new Map();
        options.set('percent', 'Show percentage of event count');
        options.set('event_count', 'Show event count');
        if (isClockEvent(eventInfo)) {
            options.set('event_count_in_ms', 'Show event count in milliseconds');
        }
        let buttons = [];
        options.forEach((value, key) => {
            buttons.push(`<button type="button" class="dropdown-item" key="${key}">${value}
                          </button>`);
        });
        this.curOption = 'percent';
        this.eventCount = eventInfo.eventCount;
        let id = createId();
        let str = `
            <div class="dropdown">
                <button type="button" class="btn btn-primary dropdown-toggle" id="${id}"
                    data-toggle="dropdown" aria-haspopup="true" aria-expanded="false"
                    >${options.get(this.curOption)}</button>
                <div class="dropdown-menu" aria-labelledby="${id}">${buttons.join('')}</div>
            </div>
        `;
        divContainer.append(str);
        divContainer.children().last().on('hidden.bs.dropdown', (e) => {
            if (e.clickEvent) {
                let button = $(e.clickEvent.target);
                let newOption = button.attr('key');
                if (newOption && this.curOption != newOption) {
                    this.curOption = newOption;
                    divContainer.find(`#${id}`).text(options.get(this.curOption));
                    onSelectChange();
                }
            }
        });
    }

    getSampleWeightFunction() {
        if (this.curOption == 'percent') {
            return (eventCount) => (eventCount * 100.0 / this.eventCount).toFixed(2) + '%';
        }
        if (this.curOption == 'event_count') {
            return (eventCount) => eventCount.toLocaleString();
        }
        if (this.curOption == 'event_count_in_ms') {
            return (eventCount) => (eventCount / 1000000.0).toFixed(3).toLocaleString();
        }
    }

    getSampleWeightSuffix() {
        if (this.curOption == 'event_count_in_ms') {
            return ' ms';
        }
        return '';
    }
}


class SampleTableView {
    constructor(divContainer, eventInfo) {
        this.id = createId();
        this.div = $('<div>', {id: this.id}).appendTo(divContainer);
        this.eventInfo = eventInfo;
        this.selectorView = null;
        this.tableDiv = null;
    }

    drawAsync(totalProgress) {
        return createPromise()
            .then(wait(() => {
                this.div.empty();
                this.selectorView = new SampleTableWeightSelectorView(
                    this.div, this.eventInfo, () => this.onSampleWeightChange());
                this.tableDiv = $('<div>').appendTo(this.div);
            }))
            .then(() => this._drawSampleTable(totalProgress));
    }

    // Return a promise to draw SampleTable.
    _drawSampleTable(totalProgress) {
        let eventInfo = this.eventInfo;
        let data = [];
        return createPromise()
            .then(wait(() => {
                this.tableDiv.empty();
                let getSampleWeight = this.selectorView.getSampleWeightFunction();
                let sampleWeightSuffix = this.selectorView.getSampleWeightSuffix();
                // Draw a table of 'Total', 'Self', 'Samples', 'Process', 'Thread', 'Library',
                // 'Function'.
                let valueSuffix = sampleWeightSuffix.length > 0 ? `(in${sampleWeightSuffix})` : '';
                let titles = ['Total' + valueSuffix, 'Self' + valueSuffix, 'Samples', 'Process',
                              'Thread', 'Library', 'Function', 'HideKey'];
                this.tableDiv.append(`
                    <table cellspacing="0" class="table table-striped table-bordered"
                        style="width:100%">
                        <thead>${getTableRow(titles, 'th')}</thead>
                        <tbody></tbody>
                        <tfoot>${getTableRow(titles, 'th')}</tfoot>
                    </table>`);
                for (let [i, process] of eventInfo.processes.entries()) {
                    let processName = getProcessName(process.pid);
                    for (let [j, thread] of process.threads.entries()) {
                        let threadName = getThreadName(thread.tid);
                        for (let [k, lib] of thread.libs.entries()) {
                            let libName = getLibName(lib.libId);
                            for (let [t, func] of lib.functions.entries()) {
                                let totalValue = getSampleWeight(func.c[2]);
                                let selfValue = getSampleWeight(func.c[1]);
                                let key = [i, j, k, t].join('_');
                                data.push([totalValue, selfValue, func.c[0], processName,
                                           threadName, libName, getFuncName(func.f), key])
                           }
                        }
                    }
                }
            }))
            .then(addProgress(totalProgress / 2))
            .then(wait(() => {
                let table = this.tableDiv.find('table');
                let dataTable = table.DataTable({
                    lengthMenu: [10, 20, 50, 100, -1],
                    pageLength: 100,
                    order: [[0, 'desc'], [1, 'desc'], [2, 'desc']],
                    data: data,
                    responsive: true,
                    columnDefs: [
                        { orderSequence: [ 'desc' ], className: 'textRight', targets: [0, 1, 2] },
                    ],
                });
                dataTable.column(7).visible(false);

                table.find('tr').css('cursor', 'pointer');
                table.on('click', 'tr', function() {
                    let data = dataTable.row(this).data();
                    if (!data) {
                        // A row in header or footer.
                        return;
                    }
                    let key = data[7];
                    if (!key) {
                        return;
                    }
                    let indexes = key.split('_');
                    let processInfo = eventInfo.processes[indexes[0]];
                    let threadInfo = processInfo.threads[indexes[1]];
                    let lib = threadInfo.libs[indexes[2]];
                    let func = lib.functions[indexes[3]];
                    FunctionTab.showFunction(eventInfo, processInfo, threadInfo, lib, func);
                });
            }));
    }

    onSampleWeightChange() {
        createPromise()
            .then(updateProgress('Draw SampleTable...', 0))
            .then(() => this._drawSampleTable(100))
            .then(hideProgress());
    }
}


// Show embedded flamegraph generated by inferno.
class FlameGraphTab {
    init(div) {
        this.div = div;
    }

    draw() {
        let views = [];
        createPromise()
            .then(updateProgress('Draw Flamegraph...', 0))
            .then(wait(() => {
                this.div.empty();
                views = createViewsForEvents(this.div, (div, eventInfo) => {
                    return new FlameGraphViewList(div, eventInfo);
                });
            }))
            .then(() => drawViewsAsync(views, 100, (view, progress) => view.drawAsync(progress)))
            .then(hideProgress());
    }
}

// Show FlameGraphs for samples in an event type, used in FlameGraphTab.
// 1. Draw 10 FlameGraphs at one time, and use a "More" button to show more FlameGraphs.
// 2. First draw background of Flamegraphs, then draw details in idle time.
class FlameGraphViewList {
    constructor(div, eventInfo) {
        this.div = div;
        this.eventInfo = eventInfo;
        this.selectorView = null;
        this.flamegraphDiv = null;
        this.flamegraphs = [];
        this.moreButton = null;
    }

    drawAsync(totalProgress) {
        this.div.empty();
        this.selectorView = new SampleWeightSelectorView(this.div, this.eventInfo,
                                                         () => this.onSampleWeightChange());
        this.flamegraphDiv = $('<div>').appendTo(this.div);
        return this._drawMoreFlameGraphs(10, totalProgress);
    }

    // Return a promise to draw flamegraphs.
    _drawMoreFlameGraphs(moreCount, progress) {
        let initProgress = progress / (1 + moreCount);
        let newFlamegraphs = [];
        return createPromise()
        .then(wait(() => {
            if (this.moreButton) {
                this.moreButton.hide();
            }
            let pId = 0;
            let tId = 0;
            let newCount = this.flamegraphs.length + moreCount;
            for (let i = 0; i < newCount; ++i) {
                if (pId == this.eventInfo.processes.length) {
                    break;
                }
                let process = this.eventInfo.processes[pId];
                let thread = process.threads[tId];
                if (i >= this.flamegraphs.length) {
                    let title = `Process ${getProcessName(process.pid)} ` +
                                `Thread ${getThreadName(thread.tid)} ` +
                                `(Samples: ${thread.sampleCount})`;
                    let totalCount = {countForProcess: process.eventCount,
                                      countForThread: thread.eventCount};
                    let flamegraph = new FlameGraphView(this.flamegraphDiv, title, totalCount,
                                                        thread.g.c, false);
                    flamegraph.draw();
                    newFlamegraphs.push(flamegraph);
                }
                tId++;
                if (tId == process.threads.length) {
                    pId++;
                    tId = 0;
                }
            }
            if (pId < this.eventInfo.processes.length) {
                // Show "More" Button.
                if (!this.moreButton) {
                    this.div.append(`
                        <div style="text-align:center">
                            <button type="button" class="btn btn-primary">More</button>
                        </div>`);
                    this.moreButton = this.div.children().last().find('button');
                    this.moreButton.click(() => {
                        createPromise().then(updateProgress('Draw FlameGraph...', 0))
                            .then(() => this._drawMoreFlameGraphs(10, 100))
                            .then(hideProgress());
                    });
                    this.moreButton.hide();
                }
            } else if (this.moreButton) {
                this.moreButton.remove();
                this.moreButton = null;
            }
            for (let flamegraph of newFlamegraphs) {
                this.flamegraphs.push(flamegraph);
            }
        }))
        .then(addProgress(initProgress))
        .then(() => this.drawDetails(newFlamegraphs, progress - initProgress));
    }

    drawDetails(flamegraphs, totalProgress) {
        return createPromise()
            .then(() => drawViewsAsync(flamegraphs, totalProgress, (view, progress) => {
                return createPromise()
                    .then(wait(() => view.drawDetails(this.selectorView.getSampleWeightFunction())))
                    .then(addProgress(progress));
            }))
            .then(wait(() => {
               if (this.moreButton) {
                   this.moreButton.show();
               }
            }));
    }

    onSampleWeightChange() {
        createPromise().then(updateProgress('Draw FlameGraph...', 0))
            .then(() => this.drawDetails(this.flamegraphs, 100))
            .then(hideProgress());
    }
}

// FunctionTab: show information of a function.
// 1. Show the callgrpah and reverse callgraph of a function as flamegraphs.
// 2. Show the annotated source code of the function.
class FunctionTab {
    static showFunction(eventInfo, processInfo, threadInfo, lib, func) {
        let title = 'Function';
        let tab = gTabs.findTab(title);
        if (!tab) {
            tab = gTabs.addTab(title, new FunctionTab());
        }
        gTabs.setActiveAsync(title)
            .then(() => tab.setFunction(eventInfo, processInfo, threadInfo, lib, func));
    }

    constructor() {
        this.func = null;
        this.selectPercent = 'thread';
    }

    init(div) {
        this.div = div;
    }

    setFunction(eventInfo, processInfo, threadInfo, lib, func) {
        this.eventInfo = eventInfo;
        this.processInfo = processInfo;
        this.threadInfo = threadInfo;
        this.lib = lib;
        this.func = func;
        this.selectorView = null;
        this.views = [];
        this.redraw();
    }

    redraw() {
        if (!this.func) {
            return;
        }
        createPromise()
            .then(updateProgress("Draw Function...", 0))
            .then(wait(() => {
                this.div.empty();
                this._drawTitle();

                this.selectorView = new SampleWeightSelectorView(this.div, this.eventInfo,
                                                                 () => this.onSampleWeightChange());
                let funcId = this.func.f;
                let funcName = getFuncName(funcId);
                function getNodesMatchingFuncId(root) {
                    let nodes = [];
                    function recursiveFn(node) {
                        if (node.f == funcId) {
                            nodes.push(node);
                        } else {
                            for (let child of node.c) {
                                recursiveFn(child);
                            }
                        }
                    }
                    recursiveFn(root);
                    return nodes;
                }
                let totalCount = {countForProcess: this.processInfo.eventCount,
                                  countForThread: this.threadInfo.eventCount};
                let callgraphView = new FlameGraphView(
                    this.div, `Functions called by ${funcName}`, totalCount,
                    getNodesMatchingFuncId(this.threadInfo.g), false);
                callgraphView.draw();
                this.views.push(callgraphView);
                let reverseCallgraphView = new FlameGraphView(
                    this.div, `Functions calling ${funcName}`, totalCount,
                    getNodesMatchingFuncId(this.threadInfo.rg), true);
                reverseCallgraphView.draw();
                this.views.push(reverseCallgraphView);
                let sourceFiles = collectSourceFilesForFunction(this.func);
                if (sourceFiles) {
                    this.div.append(getHtml('hr'));
                    this.div.append(getHtml('b', {text: 'SourceCode:'}) + '<br/>');
                    this.views.push(new SourceCodeView(this.div, sourceFiles, totalCount));
                }

                let disassembly = collectDisassemblyForFunction(this.func);
                if (disassembly) {
                    this.div.append(getHtml('hr'));
                    this.div.append(getHtml('b', {text: 'Disassembly:'}) + '<br/>');
                    this.views.push(new DisassemblyView(this.div, disassembly, totalCount));
                }
            }))
            .then(addProgress(25))
            .then(() => this.drawDetails(75))
            .then(hideProgress());
    }

    draw() {}

    _drawTitle() {
        let eventName = this.eventInfo.eventName;
        let processName = getProcessName(this.processInfo.pid);
        let threadName = getThreadName(this.threadInfo.tid);
        let libName = getLibName(this.lib.libId);
        let funcName = getFuncName(this.func.f);
        // Draw a table of 'Name', 'Value'.
        let rows = [];
        rows.push(['Event Type', eventName]);
        rows.push(['Process', processName]);
        rows.push(['Thread', threadName]);
        rows.push(['Library', libName]);
        rows.push(['Function', getHtml('pre', {text: funcName})]);
        let data = new google.visualization.DataTable();
        data.addColumn('string', '');
        data.addColumn('string', '');
        data.addRows(rows);
        for (let i = 0; i < rows.length; ++i) {
            data.setProperty(i, 0, 'className', 'boldTableCell');
        }
        let wrapperDiv = $('<div>');
        wrapperDiv.appendTo(this.div);
        let table = new google.visualization.Table(wrapperDiv.get(0));
        table.draw(data, {
            width: '100%',
            sort: 'disable',
            allowHtml: true,
            cssClassNames: {
                'tableCell': 'tableCell',
            },
        });
    }

    onSampleWeightChange() {
        createPromise()
            .then(updateProgress("Draw Function...", 0))
            .then(() => this.drawDetails(100))
            .then(hideProgress());
    }

    drawDetails(totalProgress) {
        let sampleWeightFunction = this.selectorView.getSampleWeightFunction();
        return drawViewsAsync(this.views, totalProgress, (view, progress) => {
            return createPromise()
                .then(wait(() => view.drawDetails(sampleWeightFunction)))
                .then(addProgress(progress));
        });
    }
}


// Select the way to show sample weight in FlamegraphTab and FunctionTab.
// 1. Show percentage of event count relative to all processes.
// 2. Show percentage of event count relative to the current process.
// 3. Show percentage of event count relative to the current thread.
// 4. Show absolute event count.
// 5. Show event count in milliseconds, only possible for cpu-clock or task-clock events.
class SampleWeightSelectorView {
    constructor(divContainer, eventInfo, onSelectChange) {
        let options = new Map();
        options.set('percent_to_all', 'Show percentage of event count relative to all processes');
        options.set('percent_to_process',
                    'Show percentage of event count relative to the current process');
        options.set('percent_to_thread',
                    'Show percentage of event count relative to the current thread');
        options.set('event_count', 'Show event count');
        if (isClockEvent(eventInfo)) {
            options.set('event_count_in_ms', 'Show event count in milliseconds');
        }
        let buttons = [];
        options.forEach((value, key) => {
            buttons.push(`<button type="button" class="dropdown-item" key="${key}">${value}
                          </button>`);
        });
        this.curOption = 'percent_to_all';
        let id = createId();
        let str = `
            <div class="dropdown">
                <button type="button" class="btn btn-primary dropdown-toggle" id="${id}"
                    data-toggle="dropdown" aria-haspopup="true" aria-expanded="false"
                    >${options.get(this.curOption)}</button>
                <div class="dropdown-menu" aria-labelledby="${id}">${buttons.join('')}</div>
            </div>
        `;
        divContainer.append(str);
        divContainer.children().last().on('hidden.bs.dropdown', (e) => {
            if (e.clickEvent) {
                let button = $(e.clickEvent.target);
                let newOption = button.attr('key');
                if (newOption && this.curOption != newOption) {
                    this.curOption = newOption;
                    divContainer.find(`#${id}`).text(options.get(this.curOption));
                    onSelectChange();
                }
            }
        });
        this.countForAllProcesses = eventInfo.eventCount;
    }

    getSampleWeightFunction() {
        if (this.curOption == 'percent_to_all') {
            let countForAllProcesses = this.countForAllProcesses;
            return function(eventCount, _) {
                let percent = eventCount * 100.0 / countForAllProcesses;
                return percent.toFixed(2) + '%';
            };
        }
        if (this.curOption == 'percent_to_process') {
            return function(eventCount, totalCount) {
                let percent = eventCount * 100.0 / totalCount.countForProcess;
                return percent.toFixed(2) + '%';
            };
        }
        if (this.curOption == 'percent_to_thread') {
            return function(eventCount, totalCount) {
                let percent = eventCount * 100.0 / totalCount.countForThread;
                return percent.toFixed(2) + '%';
            };
        }
        if (this.curOption == 'event_count') {
            return function(eventCount, _) {
                return eventCount.toLocaleString();
            };
        }
        if (this.curOption == 'event_count_in_ms') {
            return function(eventCount, _) {
                let timeInMs = eventCount / 1000000.0;
                return timeInMs.toFixed(3).toLocaleString() + ' ms';
            };
        }
    }
}

// Given a callgraph, show the flamegraph.
class FlameGraphView {
    constructor(divContainer, title, totalCount, initNodes, reverseOrder) {
        this.id = createId();
        this.div = $('<div>', {id: this.id,
                               style: 'font-family: Monospace; font-size: 12px'});
        this.div.appendTo(divContainer);
        this.title = title;
        this.totalCount = totalCount;
        this.reverseOrder = reverseOrder;
        this.sampleWeightFunction = null;
        this.svgNodeHeight = 17;
        this.initNodes = initNodes;
        this.sumCount = 0;
        for (let node of initNodes) {
            this.sumCount += node.s;
        }
        this.maxDepth = this._getMaxDepth(this.initNodes);
        this.svgHeight = this.svgNodeHeight * (this.maxDepth + 3);
        this.svgStr = null;
        this.svgDiv = null;
        this.svg = null;
    }

    _getMaxDepth(nodes) {
        let isArray = Array.isArray(nodes);
        let sumCount;
        if (isArray) {
            sumCount = nodes.reduce((acc, cur) => acc + cur.s, 0);
        } else {
            sumCount = nodes.s;
        }
        let width = this._getWidthPercentage(sumCount);
        if (width < 0.1) {
            return 0;
        }
        let children = isArray ? this._splitChildrenForNodes(nodes) : nodes.c;
        let childDepth = 0;
        for (let child of children) {
            childDepth = Math.max(childDepth, this._getMaxDepth(child));
        }
        return childDepth + 1;
    }

    draw() {
        // Only draw skeleton.
        this.div.empty();
        this.div.append(`<p><b>${this.title}</b></p>`);
        this.svgStr = [];
        this._renderBackground();
        this.svgStr.push('</svg></div>');
        this.div.append(this.svgStr.join(''));
        this.svgDiv = this.div.children().last();
        this.div.append('<br/><br/>');
    }

    drawDetails(sampleWeightFunction) {
        this.sampleWeightFunction = sampleWeightFunction;
        this.svgStr = [];
        this._renderBackground();
        this._renderSvgNodes();
        this._renderUnzoomNode();
        this._renderInfoNode();
        this._renderPercentNode();
        this._renderSearchNode();
        // It is much faster to add html content to svgStr than adding it directly to svgDiv.
        this.svgDiv.html(this.svgStr.join(''));
        this.svgStr = [];
        this.svg = this.svgDiv.find('svg');
        this._adjustTextSize();
        this._enableZoom();
        this._enableInfo();
        this._enableSearch();
        this._adjustTextSizeOnResize();
    }

    _renderBackground() {
        this.svgStr.push(`
            <div style="width: 100%; height: ${this.svgHeight}px;">
                <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
                    version="1.1" width="100%" height="100%" style="border: 1px solid black; ">
                        <defs > <linearGradient id="background_gradient_${this.id}"
                                  y1="0" y2="1" x1="0" x2="0" >
                                  <stop stop-color="#eeeeee" offset="5%" />
                                  <stop stop-color="#efefb1" offset="90%" />
                                  </linearGradient>
                         </defs>
                         <rect x="0" y="0" width="100%" height="100%"
                           fill="url(#background_gradient_${this.id})" />`);
    }

    _getYForDepth(depth) {
        if (this.reverseOrder) {
            return (depth + 3) * this.svgNodeHeight;
        }
        return this.svgHeight - (depth + 1) * this.svgNodeHeight;
    }

    _getWidthPercentage(eventCount) {
        return eventCount * 100.0 / this.sumCount;
    }

    _getHeatColor(widthPercentage) {
        return {
            r: Math.floor(245 + 10 * (1 - widthPercentage * 0.01)),
            g: Math.floor(110 + 105 * (1 - widthPercentage * 0.01)),
            b: 100,
        };
    }

    _renderSvgNodes() {
        let fakeNodes = [{c: this.initNodes}];
        let children = this._splitChildrenForNodes(fakeNodes);
        let xOffset = 0;
        for (let child of children) {
            xOffset = this._renderSvgNodesWithSameRoot(child, 0, xOffset);
        }
    }

    // Return an array of children nodes, with children having the same functionId merged in a
    // subarray.
    _splitChildrenForNodes(nodes) {
        let map = new Map();
        for (let node of nodes) {
            for (let child of node.c) {
                let funcName = getFuncName(child.f);
                let subNodes = map.get(funcName);
                if (subNodes) {
                    subNodes.push(child);
                } else {
                    map.set(funcName, [child]);
                }
            }
        }
        const funcNames = [...map.keys()].sort();
        let res = [];
        funcNames.forEach(function (funcName) {
            const subNodes = map.get(funcName);
            res.push(subNodes.length == 1 ? subNodes[0] : subNodes);
        });
        return res;
    }

    // nodes can be a CallNode, or an array of CallNodes with the same functionId.
    _renderSvgNodesWithSameRoot(nodes, depth, xOffset) {
        let x = xOffset;
        let y = this._getYForDepth(depth);
        let isArray = Array.isArray(nodes);
        let funcId;
        let sumCount;
        if (isArray) {
            funcId = nodes[0].f;
            sumCount = nodes.reduce((acc, cur) => acc + cur.s, 0);
        } else {
            funcId = nodes.f;
            sumCount = nodes.s;
        }
        let width = this._getWidthPercentage(sumCount);
        if (width < 0.1) {
            return xOffset;
        }
        let color = this._getHeatColor(width);
        let borderColor = {};
        for (let key in color) {
            borderColor[key] = Math.max(0, color[key] - 50);
        }
        let funcName = getFuncName(funcId);
        let libName = getLibNameOfFunction(funcId);
        let sampleWeight = this.sampleWeightFunction(sumCount, this.totalCount);
        let title = funcName + ' | ' + libName + ' (' + sumCount + ' events: ' +
                    sampleWeight + ')';
        this.svgStr.push(`<g><title>${title}</title> <rect x="${x}%" y="${y}" ox="${x}"
                        depth="${depth}" width="${width}%" owidth="${width}" height="15.0"
                        ofill="rgb(${color.r},${color.g},${color.b})"
                        fill="rgb(${color.r},${color.g},${color.b})"
                        style="stroke:rgb(${borderColor.r},${borderColor.g},${borderColor.b})"/>
                        <text x="${x}%" y="${y + 12}"></text></g>`);

        let children = isArray ? this._splitChildrenForNodes(nodes) : nodes.c;
        let childXOffset = xOffset;
        for (let child of children) {
            childXOffset = this._renderSvgNodesWithSameRoot(child, depth + 1, childXOffset);
        }
        return xOffset + width;
    }

    _renderUnzoomNode() {
        this.svgStr.push(`<rect id="zoom_rect_${this.id}" style="display:none;stroke:rgb(0,0,0);"
        rx="10" ry="10" x="10" y="10" width="80" height="30"
        fill="rgb(255,255,255)"/>
         <text id="zoom_text_${this.id}" x="19" y="30" style="display:none">Zoom out</text>`);
    }

    _renderInfoNode() {
        this.svgStr.push(`<clipPath id="info_clip_path_${this.id}">
                         <rect style="stroke:rgb(0,0,0);" rx="10" ry="10" x="120" y="10"
                         width="789" height="30" fill="rgb(255,255,255)"/>
                         </clipPath>
                         <rect style="stroke:rgb(0,0,0);" rx="10" ry="10" x="120" y="10"
                         width="799" height="30" fill="rgb(255,255,255)"/>
                         <text clip-path="url(#info_clip_path_${this.id})"
                         id="info_text_${this.id}" x="128" y="30"></text>`);
    }

    _renderPercentNode() {
        this.svgStr.push(`<rect style="stroke:rgb(0,0,0);" rx="10" ry="10"
                         x="934" y="10" width="150" height="30"
                         fill="rgb(255,255,255)"/>
                         <text id="percent_text_${this.id}" text-anchor="end"
                         x="1074" y="30"></text>`);
    }

    _renderSearchNode() {
        this.svgStr.push(`<rect style="stroke:rgb(0,0,0); rx="10" ry="10"
                         x="1150" y="10" width="80" height="30"
                         fill="rgb(255,255,255)" class="search"/>
                         <text x="1160" y="30" class="search">Search</text>`);
    }

    _adjustTextSizeForNode(g) {
        let text = g.find('text');
        let width = parseFloat(g.find('rect').attr('width')) * this.svgWidth * 0.01;
        if (width < 28) {
            text.text('');
            return;
        }
        let methodName = g.find('title').text().split(' | ')[0];
        let numCharacters;
        for (numCharacters = methodName.length; numCharacters > 4; numCharacters--) {
            if (numCharacters * 7.5 <= width) {
                break;
            }
        }
        if (numCharacters == methodName.length) {
            text.text(methodName);
        } else {
            text.text(methodName.substring(0, numCharacters - 2) + '..');
        }
    }

    _adjustTextSize() {
        this.svgWidth = $(window).width();
        let thisObj = this;
        this.svg.find('g').each(function(_, g) {
            thisObj._adjustTextSizeForNode($(g));
        });
    }

    _enableZoom() {
        this.zoomStack = [null];
        this.svg.find('g').css('cursor', 'pointer').click(zoom);
        this.svg.find(`#zoom_rect_${this.id}`).css('cursor', 'pointer').click(unzoom);
        this.svg.find(`#zoom_text_${this.id}`).css('cursor', 'pointer').click(unzoom);

        let thisObj = this;
        function zoom() {
            thisObj.zoomStack.push(this);
            displayFromElement(this);
            thisObj.svg.find(`#zoom_rect_${thisObj.id}`).css('display', 'block');
            thisObj.svg.find(`#zoom_text_${thisObj.id}`).css('display', 'block');
        }

        function unzoom() {
            if (thisObj.zoomStack.length > 1) {
                thisObj.zoomStack.pop();
                displayFromElement(thisObj.zoomStack[thisObj.zoomStack.length - 1]);
                if (thisObj.zoomStack.length == 1) {
                    thisObj.svg.find(`#zoom_rect_${thisObj.id}`).css('display', 'none');
                    thisObj.svg.find(`#zoom_text_${thisObj.id}`).css('display', 'none');
                }
            }
        }

        function displayFromElement(g) {
            let clickedOriginX = 0;
            let clickedDepth = 0;
            let clickedOriginWidth = 100;
            let scaleFactor = 1;
            if (g) {
                g = $(g);
                let clickedRect = g.find('rect');
                clickedOriginX = parseFloat(clickedRect.attr('ox'));
                clickedDepth = parseInt(clickedRect.attr('depth'));
                clickedOriginWidth = parseFloat(clickedRect.attr('owidth'));
                scaleFactor = 100.0 / clickedOriginWidth;
            }
            thisObj.svg.find('g').each(function(_, g) {
                g = $(g);
                let text = g.find('text');
                let rect = g.find('rect');
                let depth = parseInt(rect.attr('depth'));
                let ox = parseFloat(rect.attr('ox'));
                let owidth = parseFloat(rect.attr('owidth'));
                if (depth < clickedDepth || ox < clickedOriginX - 1e-9 ||
                    ox + owidth > clickedOriginX + clickedOriginWidth + 1e-9) {
                    rect.css('display', 'none');
                    text.css('display', 'none');
                } else {
                    rect.css('display', 'block');
                    text.css('display', 'block');
                    let nx = (ox - clickedOriginX) * scaleFactor + '%';
                    let ny = thisObj._getYForDepth(depth - clickedDepth);
                    rect.attr('x', nx);
                    rect.attr('y', ny);
                    rect.attr('width', owidth * scaleFactor + '%');
                    text.attr('x', nx);
                    text.attr('y', ny + 12);
                    thisObj._adjustTextSizeForNode(g);
                }
            });
        }
    }

    _enableInfo() {
        this.selected = null;
        let thisObj = this;
        this.svg.find('g').on('mouseenter', function() {
            if (thisObj.selected) {
                thisObj.selected.css('stroke-width', '0');
            }
            // Mark current node.
            let g = $(this);
            thisObj.selected = g;
            g.css('stroke', 'black').css('stroke-width', '0.5');

            // Parse title.
            let title = g.find('title').text();
            let methodAndInfo = title.split(' | ');
            thisObj.svg.find(`#info_text_${thisObj.id}`).text(methodAndInfo[0]);

            // Parse percentage.
            // '/system/lib64/libhwbinder.so (4 events: 0.28%)'
            let regexp = /.* \(.*:\s+(.*)\)/g;
            let match = regexp.exec(methodAndInfo[1]);
            let percentage = '';
            if (match && match.length > 1) {
                percentage = match[1];
            }
            thisObj.svg.find(`#percent_text_${thisObj.id}`).text(percentage);
        });
    }

    _enableSearch() {
        this.svg.find('.search').css('cursor', 'pointer').click(() => {
            let term = prompt('Search for:', '');
            if (!term) {
                this.svg.find('g > rect[ofill]').each(function() {
                    this.attributes['fill'].value = this.attributes['ofill'].value;
                });
            } else {
                this.svg.find('g').each(function() {
                    let title = this.getElementsByTagName('title')[0];
                    let rect = this.getElementsByTagName('rect')[0];
                    if (title.textContent.indexOf(term) != -1) {
                        rect.attributes['fill'].value = 'rgb(230,100,230)';
                    } else {
                        rect.attributes['fill'].value = rect.attributes['ofill'].value;
                    }
                });
            }
        });
    }

    _adjustTextSizeOnResize() {
        function throttle(callback) {
            let running = false;
            return function() {
                if (!running) {
                    running = true;
                    window.requestAnimationFrame(function () {
                        callback();
                        running = false;
                    });
                }
            };
        }
        $(window).resize(throttle(() => this._adjustTextSize()));
    }
}


class SourceFile {

    constructor(fileId) {
        this.path = getSourceFilePath(fileId);
        this.code = getSourceCode(fileId);
        this.showLines = {};  // map from line number to {eventCount, subtreeEventCount}.
        this.hasCount = false;
    }

    addLineRange(startLine, endLine) {
        for (let i = startLine; i <= endLine; ++i) {
            if (i in this.showLines || !(i in this.code)) {
                continue;
            }
            this.showLines[i] = {eventCount: 0, subtreeEventCount: 0};
        }
    }

    addLineCount(lineNumber, eventCount, subtreeEventCount) {
        let line = this.showLines[lineNumber];
        if (line) {
            line.eventCount += eventCount;
            line.subtreeEventCount += subtreeEventCount;
            this.hasCount = true;
        }
    }
}

// Return a list of SourceFile related to a function.
function collectSourceFilesForFunction(func) {
    if (!func.hasOwnProperty('s')) {
        return null;
    }
    let hitLines = func.s;
    let sourceFiles = {};  // map from sourceFileId to SourceFile.

    function getFile(fileId) {
        let file = sourceFiles[fileId];
        if (!file) {
            file = sourceFiles[fileId] = new SourceFile(fileId);
        }
        return file;
    }

    // Show lines for the function.
    let funcRange = getFuncSourceRange(func.f);
    if (funcRange) {
        let file = getFile(funcRange.fileId);
        file.addLineRange(funcRange.startLine);
    }

    // Show lines for hitLines.
    for (let hitLine of hitLines) {
        let file = getFile(hitLine.f);
        file.addLineRange(hitLine.l - 5, hitLine.l + 5);
        file.addLineCount(hitLine.l, hitLine.e, hitLine.s);
    }

    let result = [];
    // Show the source file containing the function before other source files.
    if (funcRange) {
        let file = getFile(funcRange.fileId);
        if (file.hasCount) {
            result.push(file);
        }
        delete sourceFiles[funcRange.fileId];
    }
    for (let fileId in sourceFiles) {
        let file = sourceFiles[fileId];
        if (file.hasCount) {
            result.push(file);
        }
    }
    return result.length > 0 ? result : null;
}

// Show annotated source code of a function.
class SourceCodeView {

    constructor(divContainer, sourceFiles, totalCount) {
        this.div = $('<div>');
        this.div.appendTo(divContainer);
        this.sourceFiles = sourceFiles;
        this.totalCount = totalCount;
    }

    drawDetails(sampleWeightFunction) {
        google.charts.setOnLoadCallback(() => this.realDraw(sampleWeightFunction));
    }

    realDraw(sampleWeightFunction) {
        this.div.empty();
        // For each file, draw a table of 'Line', 'Total', 'Self', 'Code'.
        for (let sourceFile of this.sourceFiles) {
            let rows = [];
            let lineNumbers = Object.keys(sourceFile.showLines);
            lineNumbers.sort((a, b) => a - b);
            for (let lineNumber of lineNumbers) {
                let code = getHtml('pre', {text: sourceFile.code[lineNumber]});
                let countInfo = sourceFile.showLines[lineNumber];
                let totalValue = '';
                let selfValue = '';
                if (countInfo.subtreeEventCount != 0) {
                    totalValue = sampleWeightFunction(countInfo.subtreeEventCount, this.totalCount);
                    selfValue = sampleWeightFunction(countInfo.eventCount, this.totalCount);
                }
                rows.push([lineNumber, totalValue, selfValue, code]);
            }

            let data = new google.visualization.DataTable();
            data.addColumn('string', 'Line');
            data.addColumn('string', 'Total');
            data.addColumn('string', 'Self');
            data.addColumn('string', 'Code');
            data.addRows(rows);
            data.setColumnProperty(0, 'className', 'colForLine');
            data.setColumnProperty(1, 'className', 'colForCount');
            data.setColumnProperty(2, 'className', 'colForCount');
            this.div.append(getHtml('pre', {text: sourceFile.path}));
            let wrapperDiv = $('<div>');
            wrapperDiv.appendTo(this.div);
            let table = new google.visualization.Table(wrapperDiv.get(0));
            table.draw(data, {
                width: '100%',
                sort: 'disable',
                frozenColumns: 3,
                allowHtml: true,
            });
        }
    }
}

// Return a list of disassembly related to a function.
function collectDisassemblyForFunction(func) {
    if (!func.hasOwnProperty('a')) {
        return null;
    }
    let hitAddrs = func.a;
    let rawCode = getFuncDisassembly(func.f);
    if (!rawCode) {
        return null;
    }

    // Annotate disassembly with event count information.
    let annotatedCode = [];
    let codeForLastAddr = null;
    let hitAddrPos = 0;
    let hasCount = false;

    function addEventCount(addr) {
        while (hitAddrPos < hitAddrs.length && BigInt(hitAddrs[hitAddrPos].a) < addr) {
            if (codeForLastAddr) {
                codeForLastAddr.eventCount += hitAddrs[hitAddrPos].e;
                codeForLastAddr.subtreeEventCount += hitAddrs[hitAddrPos].s;
                hasCount = true;
            }
            hitAddrPos++;
        }
    }

    for (let line of rawCode) {
        let code = line[0];
        let addr = BigInt(line[1]);

        addEventCount(addr);
        let item = {code: code, eventCount: 0, subtreeEventCount: 0};
        annotatedCode.push(item);
        // Objdump sets addr to 0 when a disassembly line is not associated with an addr.
        if (addr != 0) {
            codeForLastAddr = item;
        }
    }
    addEventCount(Number.MAX_VALUE);
    return hasCount ? annotatedCode : null;
}

// Show annotated disassembly of a function.
class DisassemblyView {

    constructor(divContainer, disassembly, totalCount) {
        this.div = $('<div>');
        this.div.appendTo(divContainer);
        this.disassembly = disassembly;
        this.totalCount = totalCount;
    }

    drawDetails(sampleWeightFunction) {
        google.charts.setOnLoadCallback(() => this.realDraw(sampleWeightFunction));
    }

    realDraw(sampleWeightFunction) {
        this.div.empty();
        // Draw a table of 'Total', 'Self', 'Code'.
        let rows = [];
        for (let line of this.disassembly) {
            let code = getHtml('pre', {text: line.code});
            let totalValue = '';
            let selfValue = '';
            if (line.subtreeEventCount != 0) {
                totalValue = sampleWeightFunction(line.subtreeEventCount, this.totalCount);
                selfValue = sampleWeightFunction(line.eventCount, this.totalCount);
            }
            rows.push([totalValue, selfValue, code]);
        }
        let data = new google.visualization.DataTable();
        data.addColumn('string', 'Total');
        data.addColumn('string', 'Self');
        data.addColumn('string', 'Code');
        data.addRows(rows);
        data.setColumnProperty(0, 'className', 'colForCount');
        data.setColumnProperty(1, 'className', 'colForCount');
        let wrapperDiv = $('<div>');
        wrapperDiv.appendTo(this.div);
        let table = new google.visualization.Table(wrapperDiv.get(0));
        table.draw(data, {
            width: '100%',
            sort: 'disable',
            frozenColumns: 2,
            allowHtml: true,
        });
    }
}


// FrameGraph tab: show per-frame analysis with good/bad frame classification.
class FrameGraphTab {
    init(div) {
        this.div = div;
    }

    draw() {
        this.div.empty();
        // Target FPS control
        let controlDiv = $('<div class="ml-3 mt-2 mb-2">').appendTo(this.div);
        controlDiv.append('<label class="mr-2"><b>Target FPS:</b></label>');
        let fpsInput = $('<input type="number" value="60" min="1" max="240" style="width:80px" class="form-control d-inline-block">');
        fpsInput.appendTo(controlDiv);
        this.targetFps = 60;
        this.views = [];

        fpsInput.on('change', () => {
            let val = parseInt(fpsInput.val());
            if (val > 0 && val <= 240) {
                this.targetFps = val;
                for (let view of this.views) {
                    view.updateTargetFps(this.targetFps);
                }
            }
        });

        // Create one FrameGraphView per thread across all events.
        for (let eventData of gFrameGraphData) {
            for (let threadData of eventData.threads) {
                let title = `${eventData.eventName} — ${threadData.threadName} ` +
                            `(pid:${threadData.pid} tid:${threadData.tid}) ` +
                            `marker: ${threadData.markerFunc} — ${threadData.frames.length} frames`;
                let view = new FrameGraphView(this.div, title, threadData, this.targetFps);
                view.draw();
                this.views.push(view);
            }
        }
    }
}

// Render a flamegraph-like view colored by frame analysis deltas.
class FrameGraphView {
    constructor(divContainer, title, threadData, targetFps) {
        this.id = createId();
        this.div = $('<div>', {id: this.id, style: 'font-family: Monospace; font-size: 12px'});
        this.div.appendTo(divContainer);
        this.title = title;
        this.threadData = threadData;
        this.targetFps = targetFps;
        this.frames = threadData.frames; // [[total_period, [fid, self, subtree, ...]], ...]
        this.svgNodeHeight = 32;
    }

    draw() {
        this.div.empty();
        this._computeStats();
        this._render();
    }

    updateTargetFps(fps) {
        this.targetFps = fps;
        this._computeStats();
        this._render();
    }

    _computeStats() {
        let frameBudget = 1e9 / this.targetFps; // ns
        this.goodFrames = [];
        this.badFrames = [];

        for (let frame of this.frames) {
            let totalPeriod = frame[0];
            if (totalPeriod <= frameBudget) {
                this.goodFrames.push(frame);
            } else {
                this.badFrames.push(frame);
            }
        }

        // Build per-function aggregated stats across all frames.
        // funcStats: Map<funcId, {totalSubtree, goodSubtreeSum, goodCount, badSubtreeSum, badCount,
        //                         minFrame, maxFrame, frameValues: [{frameIdx, valueMs}]}>
        this.funcStats = new Map();
        let self_ = this;

        function processFrame(frame, isBad, frameIdx) {
            let d = frame[1]; // [fid, self, subtree, fid, self, subtree, ...]
            for (let i = 0; i < d.length; i += 3) {
                let fid = d[i];
                let selfNs = d[i+1];
                let subtreeNs = d[i+2];
                let stat = self_.funcStats.get(fid);
                if (!stat) {
                    stat = {totalSubtree: 0, goodSubtreeSum: 0, goodCount: 0,
                            badSubtreeSum: 0, badCount: 0, minFrame: Infinity, maxFrame: 0,
                            frameValues: []};
                    self_.funcStats.set(fid, stat);
                }
                stat.totalSubtree += subtreeNs;
                let frameTotalNs = frame[0];
                let ratio = frameTotalNs > 0 ? subtreeNs / frameTotalNs : 0;
                stat.frameValues.push({frameIdx: frameIdx, valueMs: subtreeNs / 1e6, ratio: ratio});
                if (isBad) {
                    stat.badSubtreeSum += subtreeNs;
                    stat.badCount++;
                } else {
                    stat.goodSubtreeSum += subtreeNs;
                    stat.goodCount++;
                }
                if (subtreeNs < stat.minFrame) stat.minFrame = subtreeNs;
                if (subtreeNs > stat.maxFrame) stat.maxFrame = subtreeNs;
            }
        }

        for (let i = 0; i < this.frames.length; i++) {
            let frame = this.frames[i];
            let isBad = frame[0] > frameBudget;
            processFrame(frame, isBad, i);
        }

        // Compute delta, CV, and max CV for color scaling.
        this.maxCv = 0;
        for (let [fid, stat] of this.funcStats) {
            let avgBad = stat.badCount > 0 ? stat.badSubtreeSum / stat.badCount : 0;
            let avgGood = stat.goodCount > 0 ? stat.goodSubtreeSum / stat.goodCount : 0;
            stat.delta = avgBad - avgGood;

            // Compute avg, median, stddev from absolute frameValues (ns).
            let vals = stat.frameValues.map(fv => fv.valueMs * 1e6); // back to ns for consistency
            let n = vals.length;
            let sum = 0;
            for (let v of vals) sum += v;
            stat.avg = sum / n;

            let sorted = vals.slice().sort((a, b) => a - b);
            if (n % 2 === 1) {
                stat.median = sorted[Math.floor(n / 2)];
            } else {
                stat.median = (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
            }

            let sqSum = 0;
            for (let v of vals) { let d = v - stat.avg; sqSum += d * d; }
            stat.stddev = Math.sqrt(sqSum / n);

            // CV based on frame-time ratio (subtreeNs/frameTotalNs) to eliminate
            // frame duration variation — only captures true instability.
            let ratios = stat.frameValues.map(fv => fv.ratio);
            let rSum = 0;
            for (let r of ratios) rSum += r;
            let rAvg = rSum / ratios.length;
            let rSqSum = 0;
            for (let r of ratios) { let d = r - rAvg; rSqSum += d * d; }
            let rStddev = Math.sqrt(rSqSum / ratios.length);
            stat.cv = rAvg > 0 ? rStddev / rAvg : 0;
            if (stat.cv > this.maxCv) this.maxCv = stat.cv;
        }
    }

    _getDeltaColor(funcId) {
        let stat = this.funcStats.get(funcId);
        if (!stat || this.maxCv <= 0 || stat.cv <= 0) {
            // Neutral: light gray-blue
            return {r: 200, g: 210, b: 230};
        }
        let intensity = Math.min(1.0, stat.cv / this.maxCv);
        // Interpolate from light gray-blue (200,210,230) to deep red (220,60,60)
        let r = Math.floor(200 + 20 * intensity);
        let g = Math.floor(210 - 150 * intensity);
        let b = Math.floor(230 - 170 * intensity);
        return {r, g, b};
    }

    _render() {
        this.div.empty();

        let frameBudgetMs = (1000 / this.targetFps).toFixed(2);
        let totalFrames = this.frames.length;
        let goodCount = this.goodFrames.length;
        let badCount = this.badFrames.length;

        this.div.append(`<p><b>${this.title}</b></p>`);
        this.div.append(`<p class="ml-3">Total frames: ${totalFrames} | ` +
            `Good: ${goodCount} (≤${frameBudgetMs}ms) | ` +
            `Bad: <span style="color:red">${badCount}</span> (&gt;${frameBudgetMs}ms)</p>`);

        if (totalFrames === 0) {
            this.div.append('<p class="ml-3 text-muted">No frames detected.</p>');
            return;
        }

        // Use the call tree from sampleInfo to get the flamegraph structure.
        // Find the matching thread in sampleInfo.
        let callTree = this._findCallTree();
        if (!callTree) {
            this.div.append('<p class="ml-3 text-muted">No matching call tree found in sample data.</p>');
            return;
        }

        // Compute total subtree for width calculation.
        this.sumCount = 0;
        for (let node of callTree) {
            this.sumCount += node.s;
        }

        this.maxDepth = this._getMaxDepth(callTree);
        this.svgHeight = this.svgNodeHeight * (this.maxDepth + 3);
        this.svgStr = [];

        // Render SVG.
        this.svgStr.push(`
            <div style="width: 100%; height: ${this.svgHeight}px;">
                <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
                    version="1.1" width="100%" height="100%" style="border: 1px solid black;">
                    <defs><linearGradient id="fg_bg_${this.id}" y1="0" y2="1" x1="0" x2="0">
                        <stop stop-color="#eeeeff" offset="5%"/>
                        <stop stop-color="#e0e0f0" offset="90%"/>
                    </linearGradient></defs>
                    <rect x="0" y="0" width="100%" height="100%" fill="url(#fg_bg_${this.id})"/>`);

        // Render nodes.
        let fakeNodes = [{c: callTree}];
        let children = this._splitChildrenForNodes(fakeNodes);
        let xOffset = 0;
        for (let child of children) {
            xOffset = this._renderNode(child, 0, xOffset);
        }

        // Unzoom, info, search controls.
        this.svgStr.push(`<rect id="fg_zoom_rect_${this.id}" style="display:none;stroke:rgb(0,0,0);"
            rx="10" ry="10" x="10" y="10" width="80" height="30" fill="rgb(255,255,255)"/>
            <text id="fg_zoom_text_${this.id}" x="19" y="30" style="display:none">Zoom out</text>`);

        this.svgStr.push(`<clipPath id="fg_info_clip_${this.id}">
            <rect rx="10" ry="10" x="120" y="10" width="789" height="30" fill="rgb(255,255,255)"/>
            </clipPath>
            <rect style="stroke:rgb(0,0,0);" rx="10" ry="10" x="120" y="10" width="799" height="30" fill="rgb(255,255,255)"/>
            <text clip-path="url(#fg_info_clip_${this.id})" id="fg_info_text_${this.id}" x="128" y="30"></text>`);

        this.svgStr.push(`<rect style="stroke:rgb(0,0,0);" rx="10" ry="10" x="934" y="10" width="150" height="30" fill="rgb(255,255,255)"/>
            <text id="fg_percent_text_${this.id}" text-anchor="end" x="1074" y="30"></text>`);

        this.svgStr.push(`<rect style="stroke:rgb(0,0,0);" rx="10" ry="10" x="1150" y="10" width="80" height="30"
            fill="rgb(255,255,255)" class="fg-search"/>
            <text x="1160" y="30" class="fg-search">Search</text>`);

        this.svgStr.push('</svg></div>');

        this.div.append(this.svgStr.join(''));
        this.svgStr = [];
        this.svgDiv = this.div.children().last();
        this.svg = this.svgDiv.find('svg');
        this.div.append('<br/>');

        this._adjustTextSize();
        this._enableZoom();
        this._enableInfo();
        this._enableSearch();
        this._enableChartButtons();
        this._adjustTextSizeOnResize();
    }

    _findCallTree() {
        // Find matching thread in sampleInfo by pid/tid.
        for (let eventInfo of gSampleInfo) {
            for (let process of eventInfo.processes) {
                for (let thread of process.threads) {
                    if (thread.tid === this.threadData.tid) {
                        return thread.g.c;
                    }
                }
            }
        }
        return null;
    }

    _getYForDepth(depth) {
        return this.svgHeight - (depth + 1) * this.svgNodeHeight;
    }

    _getWidthPercentage(eventCount) {
        return eventCount * 100.0 / this.sumCount;
    }

    _getMaxDepth(nodes) {
        let isArray = Array.isArray(nodes);
        let sumCount = isArray ? nodes.reduce((a, c) => a + c.s, 0) : nodes.s;
        let width = this._getWidthPercentage(sumCount);
        if (width < 0.1) return 0;
        let children = isArray ? this._splitChildrenForNodes(nodes) : nodes.c;
        let childDepth = 0;
        for (let child of children) {
            childDepth = Math.max(childDepth, this._getMaxDepth(child));
        }
        return childDepth + 1;
    }

    _splitChildrenForNodes(nodes) {
        let map = new Map();
        for (let node of nodes) {
            for (let child of node.c) {
                let funcName = getFuncName(child.f);
                let subNodes = map.get(funcName);
                if (subNodes) {
                    subNodes.push(child);
                } else {
                    map.set(funcName, [child]);
                }
            }
        }
        const funcNames = [...map.keys()].sort();
        let res = [];
        funcNames.forEach(funcName => {
            const subNodes = map.get(funcName);
            res.push(subNodes.length === 1 ? subNodes[0] : subNodes);
        });
        return res;
    }

    _renderNode(nodes, depth, xOffset) {
        let x = xOffset;
        let y = this._getYForDepth(depth);
        let isArray = Array.isArray(nodes);
        let funcId = isArray ? nodes[0].f : nodes.f;
        let sumCount = isArray ? nodes.reduce((a, c) => a + c.s, 0) : nodes.s;
        let width = this._getWidthPercentage(sumCount);
        if (width < 0.1) return xOffset;

        let color = this._getDeltaColor(funcId);
        let borderColor = {};
        for (let key in color) {
            borderColor[key] = Math.max(0, color[key] - 50);
        }

        let funcName = getFuncName(funcId);
        let libName = getLibNameOfFunction(funcId);
        let stat = this.funcStats.get(funcId);
        let tooltip = funcName + ' | ' + libName;
        if (stat) {
            let minMs = (stat.minFrame / 1e6).toFixed(3);
            let maxMs = (stat.maxFrame / 1e6).toFixed(3);
            let deltaMs = (stat.delta / 1e6).toFixed(3);
            tooltip += ` | min: ${minMs}ms | max: ${maxMs}ms | \u0394bad: ${deltaMs}ms`;
        }

        this.svgStr.push(`<g data-fid="${funcId}"><title>${tooltip}</title><rect x="${x}%" y="${y}" ox="${x}"
            depth="${depth}" width="${width}%" owidth="${width}" height="28.0"
            ofill="rgb(${color.r},${color.g},${color.b})"
            fill="rgb(${color.r},${color.g},${color.b})"
            style="stroke:rgb(${borderColor.r},${borderColor.g},${borderColor.b})"/>
            <rect class="chart-btn" x="0" y="${y+2}" width="14" height="24"
                rx="2" fill="rgba(0,0,0,0.15)" style="cursor:pointer;display:none"/>
            <text class="chart-icon" x="0" y="${y+18}"
                style="font-size:14px;pointer-events:none;display:none">📈</text>
            <text class="fn" x="${x}%" y="${y + 12}"></text>
            <text class="st" x="${x}%" y="${y + 24}"></text></g>`);

        let children = isArray ? this._splitChildrenForNodes(nodes) : nodes.c;
        let childXOffset = xOffset;
        for (let child of children) {
            childXOffset = this._renderNode(child, depth + 1, childXOffset);
        }
        return xOffset + width;
    }

    _adjustTextSizeForNode(g) {
        let fnText = g.find('text.fn');
        let stText = g.find('text.st');
        let chartBtn = g.find('rect.chart-btn');
        let chartIcon = g.find('text.chart-icon');
        let mainRect = g.find('rect').first();
        let width = parseFloat(mainRect.attr('width')) * this.svgWidth * 0.01;
        if (width < 28) {
            fnText.text(''); stText.text('');
            chartBtn.css('display', 'none'); chartIcon.css('display', 'none');
            return;
        }

        let methodName = g.find('title').text().split(' | ')[0];
        let fid = parseInt(g.attr('data-fid'));
        let stat = this.funcStats.get(fid);

        // Show chart button if wide enough.
        let btnWidth = 0;
        if (width > 50 && stat && stat.frameValues.length > 1) {
            let rectXPct = parseFloat(mainRect.attr('x'));
            let rectXPx = rectXPct * this.svgWidth * 0.01;
            let rectY = parseFloat(mainRect.attr('y'));
            // Position button at right edge of the node (pixel coordinates).
            let btnX = rectXPx + width - 16;
            chartBtn.attr('x', btnX).attr('y', rectY + 2).css('display', 'block');
            chartIcon.attr('x', btnX + 1).attr('y', rectY + 18).css('display', 'block');
            btnWidth = 18;
        } else {
            chartBtn.css('display', 'none'); chartIcon.css('display', 'none');
        }

        let textWidth = width - btnWidth;

        // Build stats string.
        let statsStr = '';
        if (stat) {
            let minMs = (stat.minFrame / 1e6).toFixed(2);
            let maxMs = (stat.maxFrame / 1e6).toFixed(2);
            let avgMs = (stat.avg / 1e6).toFixed(2);
            let medMs = (stat.median / 1e6).toFixed(2);
            let sdMs = (stat.stddev / 1e6).toFixed(2);
            statsStr = `min:${minMs}  max:${maxMs}  avg:${avgMs}  med:${medMs}  \u03C3:${sdMs} (ms)`;
        }

        // Try single line: funcName + stats together.
        if (statsStr) {
            let combined = methodName + '  ' + statsStr;
            if (combined.length * 7.5 <= textWidth) {
                fnText.text(combined);
                stText.text('');
                return;
            }
        }

        // Won't fit on one line — truncate funcName for line 1.
        let numChars;
        for (numChars = methodName.length; numChars > 4; numChars--) {
            if (numChars * 7.5 <= textWidth) break;
        }
        fnText.text(numChars === methodName.length ? methodName : methodName.substring(0, numChars - 2) + '..');

        // Line 2: stats (full or short depending on width).
        if (!statsStr || textWidth < 120) {
            stText.text('');
            return;
        }
        let statsChars = statsStr.length;
        if (statsChars * 7.5 <= textWidth) {
            stText.text(statsStr);
        } else {
            // Short version.
            let minMs = (stat.minFrame / 1e6).toFixed(2);
            let maxMs = (stat.maxFrame / 1e6).toFixed(2);
            let avgMs = (stat.avg / 1e6).toFixed(2);
            let shortStr = `min:${minMs} max:${maxMs} avg:${avgMs}`;
            if (shortStr.length * 7.5 <= textWidth) {
                stText.text(shortStr);
            } else {
                stText.text('');
            }
        }
    }

    _adjustTextSize() {
        this.svgWidth = $(window).width();
        let self_ = this;
        this.svg.find('g').each(function(_, g) { self_._adjustTextSizeForNode($(g)); });
    }

    _enableZoom() {
        this.zoomStack = [null];
        this.svg.find('g').css('cursor', 'pointer').click(zoom);
        this.svg.find(`#fg_zoom_rect_${this.id}`).css('cursor', 'pointer').click(unzoom);
        this.svg.find(`#fg_zoom_text_${this.id}`).css('cursor', 'pointer').click(unzoom);

        let self_ = this;
        function zoom() {
            self_.zoomStack.push(this);
            displayFromElement(this);
            self_.svg.find(`#fg_zoom_rect_${self_.id}`).css('display', 'block');
            self_.svg.find(`#fg_zoom_text_${self_.id}`).css('display', 'block');
        }
        function unzoom() {
            if (self_.zoomStack.length > 1) {
                self_.zoomStack.pop();
                displayFromElement(self_.zoomStack[self_.zoomStack.length - 1]);
                if (self_.zoomStack.length === 1) {
                    self_.svg.find(`#fg_zoom_rect_${self_.id}`).css('display', 'none');
                    self_.svg.find(`#fg_zoom_text_${self_.id}`).css('display', 'none');
                }
            }
        }
        function displayFromElement(g) {
            let clickedOriginX = 0, clickedDepth = 0, clickedOriginWidth = 100, scaleFactor = 1;
            if (g) {
                g = $(g);
                let clickedRect = g.find('rect');
                clickedOriginX = parseFloat(clickedRect.attr('ox'));
                clickedDepth = parseInt(clickedRect.attr('depth'));
                clickedOriginWidth = parseFloat(clickedRect.attr('owidth'));
                scaleFactor = 100.0 / clickedOriginWidth;
            }
            self_.svg.find('g').each(function(_, g) {
                g = $(g);
                let fnText = g.find('text.fn');
                let stText = g.find('text.st');
                let chartBtn = g.find('rect.chart-btn');
                let chartIcon = g.find('text.chart-icon');
                let rect = g.find('rect').first();
                let depth = parseInt(rect.attr('depth'));
                let ox = parseFloat(rect.attr('ox'));
                let owidth = parseFloat(rect.attr('owidth'));
                if (depth < clickedDepth || ox < clickedOriginX - 1e-9 ||
                    ox + owidth > clickedOriginX + clickedOriginWidth + 1e-9) {
                    rect.css('display', 'none');
                    fnText.css('display', 'none');
                    stText.css('display', 'none');
                    chartBtn.css('display', 'none');
                    chartIcon.css('display', 'none');
                } else {
                    rect.css('display', 'block');
                    fnText.css('display', 'block');
                    stText.css('display', 'block');
                    let nx = (ox - clickedOriginX) * scaleFactor + '%';
                    let ny = self_._getYForDepth(depth - clickedDepth);
                    rect.attr('x', nx); rect.attr('y', ny);
                    rect.attr('width', owidth * scaleFactor + '%');
                    fnText.attr('x', nx); fnText.attr('y', ny + 12);
                    stText.attr('x', nx); stText.attr('y', ny + 24);
                    self_._adjustTextSizeForNode(g);
                }
            });
        }
    }

    _enableInfo() {
        this.selected = null;
        let self_ = this;
        this.svg.find('g').on('mouseenter', function() {
            if (self_.selected) self_.selected.css('stroke-width', '0');
            let g = $(this);
            self_.selected = g;
            g.css('stroke', 'black').css('stroke-width', '0.5');
            let title = g.find('title').text();
            let parts = title.split(' | ');
            self_.svg.find(`#fg_info_text_${self_.id}`).text(parts[0]);
            // Show delta info in percent area.
            let deltaInfo = parts.length >= 4 ? parts.slice(2).join(' | ') : '';
            self_.svg.find(`#fg_percent_text_${self_.id}`).text(deltaInfo);
        });
    }

    _enableSearch() {
        this.svg.find('.fg-search').css('cursor', 'pointer').click(() => {
            let term = prompt('Search for:', '');
            if (!term) {
                this.svg.find('g > rect[ofill]').each(function() {
                    this.attributes['fill'].value = this.attributes['ofill'].value;
                });
            } else {
                this.svg.find('g').each(function() {
                    let title = this.getElementsByTagName('title')[0];
                    let rect = this.getElementsByTagName('rect')[0];
                    if (title.textContent.indexOf(term) !== -1) {
                        rect.attributes['fill'].value = 'rgb(230,100,230)';
                    } else {
                        rect.attributes['fill'].value = rect.attributes['ofill'].value;
                    }
                });
            }
        });
    }

    _adjustTextSizeOnResize() {
        let self_ = this;
        function throttle(callback) {
            let running = false;
            return function() {
                if (!running) {
                    running = true;
                    window.requestAnimationFrame(function() {
                        callback();
                        running = false;
                    });
                }
            };
        }
        $(window).resize(throttle(() => self_._adjustTextSize()));
    }

    _enableChartButtons() {
        let self_ = this;
        this.svg.find('rect.chart-btn').click(function(e) {
            e.stopPropagation();
            let g = $(this).closest('g');
            let fid = parseInt(g.attr('data-fid'));
            self_._showFrameChart(fid);
        });
    }

    _showFrameChart(funcId) {
        let stat = this.funcStats.get(funcId);
        if (!stat) return;
        let funcName = getFuncName(funcId);

        // Remove existing overlay.
        this.div.find('.frame-chart-overlay').remove();

        // Build overlay.
        let overlay = $('<div>', {class: 'frame-chart-overlay'})
            .css({position:'fixed', top:'10%', left:'10%', width:'80%', height:'70%',
                  background:'white', border:'2px solid #333', borderRadius:'8px',
                  zIndex:9999, padding:'12px', boxShadow:'0 4px 20px rgba(0,0,0,0.3)'});

        let header = $('<div>').css({display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'8px'});
        header.append($('<b>').text(funcName));
        header.append($('<button>').text('\u2715').css({border:'none', background:'none', fontSize:'18px', cursor:'pointer'})
            .click(() => overlay.remove()));
        overlay.append(header);

        let chartDiv = $('<div>').css({width:'100%', height:'calc(100% - 40px)'});
        overlay.append(chartDiv);
        this.div.append(overlay);

        // Sort by frameIdx for correct ordering.
        let sorted = stat.frameValues.slice().sort((a, b) => a.frameIdx - b.frameIdx);

        let data = new google.visualization.DataTable();
        data.addColumn('number', 'Frame');
        data.addColumn('number', 'ms');
        for (let fv of sorted) {
            data.addRow([fv.frameIdx, fv.valueMs]);
        }
        let chart = new google.visualization.LineChart(chartDiv[0]);
        chart.draw(data, {
            title: funcName + ' \u2014 Per-Frame Execution Time',
            hAxis: {title: 'Frame'},
            vAxis: {title: 'ms'},
            legend: 'none',
            pointSize: 1,
            lineWidth: 1,
            chartArea: {left:60, top:40, right:20, bottom:40}
        });

        // ESC to close.
        let escHandler = function(e) {
            if (e.key === 'Escape') {
                overlay.remove();
                $(document).off('keydown', escHandler);
            }
        };
        $(document).on('keydown', escHandler);
    }
}


function initGlobalObjects() {
    let recordData = $('#record_data').text();
    gRecordInfo = JSON.parse(recordData);
    gProcesses = gRecordInfo.processNames;
    gThreads = gRecordInfo.threadNames;
    gLibList = gRecordInfo.libList;
    gFunctionMap = gRecordInfo.functionMap;
    gSampleInfo = gRecordInfo.sampleInfo;
    gSourceFiles = gRecordInfo.sourceFiles;
    gFrameGraphData = gRecordInfo.frameGraphData || [];
}

function createTabs() {
    gTabs = new TabManager($('div#report_content'));
    gTabs.addTab('Chart Statistics', new ChartStatTab());
    gTabs.addTab('Sample Table', new SampleTableTab());
    gTabs.addTab('Flamegraph', new FlameGraphTab());
    if (gFrameGraphData.length > 0) {
        gTabs.addTab('FrameGraph', new FrameGraphTab());
    }
}

// Global draw objects
let gTabs;
let gProgressBar = new ProgressBar();

// Gobal Json Data
let gRecordInfo;
let gProcesses;
let gThreads;
let gLibList;
let gFunctionMap;
let gSampleInfo;
let gSourceFiles;
let gFrameGraphData;

function updateProgress(text, progress) {
    return () => gProgressBar.updateAsync(text, progress);
}

function addProgress(progress) {
    return () => gProgressBar.updateAsync(null, gProgressBar.progress + progress);
}

function hideProgress() {
    return () => gProgressBar.hide();
}

function createPromise(callback) {
    if (callback) {
        return new Promise((resolve, _) => callback(resolve));
    }
    return new Promise((resolve,_) => resolve());
}

function waitDocumentReady() {
    return createPromise((resolve) => $(document).ready(resolve));
}

function wait(functionCall) {
    return () => {
        functionCall();
        return createPromise();
    };
}

createPromise()
    .then(updateProgress('Load page...', 0))
    .then(waitDocumentReady)
    .then(updateProgress('Parse Json data...', 20))
    .then(wait(initGlobalObjects))
    .then(updateProgress('Create tabs...', 30))
    .then(wait(createTabs))
    .then(updateProgress('Draw ChartStat...', 40))
    .then(() => gTabs.setActiveAsync('Chart Statistics'))
    .then(updateProgress(null, 100))
    .then(hideProgress());
})();
