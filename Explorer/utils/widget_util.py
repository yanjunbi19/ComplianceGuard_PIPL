from collections.abc import Iterable
import re
from loguru import logger

def convert_class_to_text_label(the_class_of_text):
    # IMPORTANT: original dict had many duplicate keys (TextView/ImageView/CheckedTextView),
    # Python keeps the last one -> silently breaks labeling.
    lookup = {
        "AdView": 1,
        "HtmlBannerWebView": 1,
        "AdContainer": 1,

        "BottomTagGroupView": 3,
        "BottomBar": 3,
        "ButtonBar": 4,
        "CardView": 5,

        "CheckBox": 6,
        "CheckedTextView": 18,
        "DrawerLayout": 7,
        "DatePicker": 8,

        "ImageView": 9,
        "ImageButton": 10,
        "GlyphView": 10,
        "AppCompactButton": 10,
        "AppCompactImageButton": 10,
        "ActionMenuItemView": 10,
        "ActionMenuItemPresenter": 10,

        # Text/Input baseline is 11; "clickable TextView as Button" handled in parse_widgets()
        "TextView": 11,
        "EditText": 11,
        "SearchBoxView": 11,
        "AutoCompleteTextView": 11,
        "AppCompatAutoCompleteTextView": 11,
        "MultiAutoCompleteTextView": 11,

        "ListView": 12,
        "RecyclerView": 12,
        "ListPopUpWindow": 12,
        "tabItem": 12,
        "GridView": 12,

        "MapView": 13,
        "SlidingTab": 14,
        "NumberPicker": 15,
        "Switch": 16,

        "ViewPageIndicatorDots": 17,
        "PageIndicator": 17,
        "CircleIndicator": 17,
        "PagerIndicator": 17,

        "RadioButton": 18,
        "SeekBar": 19,
        "Button": 20,

        "ToolBar": 21,
        "TitleBar": 21,
        "ActionBar": 21,

        "VideoView": 22,
        "WebView": 23,
    }
    the_class_of_text = (the_class_of_text or "").split(".")[-1]
    if the_class_of_text in lookup:
        return lookup[the_class_of_text]
    for k, v in lookup.items():
        if the_class_of_text.endswith(k):
            return v
    return 0


def _simple_class(cls):
    return (cls or "").split(".")[-1]


def _is_true(v):
    return str(v).lower() == "true"


def _is_input_class(simple_cls):
    if not simple_cls:
        return False
    if simple_cls in (
        "EditText",
        "AutoCompleteTextView",
        "AppCompatAutoCompleteTextView",
        "MultiAutoCompleteTextView",
        "SearchView",
        "SearchAutoComplete",
    ):
        return True
    if simple_cls.endswith("EditText") or simple_cls.endswith("AutoCompleteTextView"):
        return True
    return False


def is_input_like_item(item):
    """
    item schema (from parse_widgets):
      [text, text_class, bounds, operatable, resource_id, the_class, scrollable, content_desc, index]
    """
    try:
        text = str(item[0] or "").lower()
        rid = str(item[4] or "").lower()
        cls = str(item[5] or "")
        desc = str(item[7] or "").lower()
        simple_cls = _simple_class(cls)

        if _is_input_class(simple_cls):
            return True

        blob = " ".join([text, rid, desc, simple_cls.lower()])
        keys = (
            "search", "query", "keyword", "filter", "input",
            "请输入", "搜索", "查询", "关键字", "筛选",
        )
        return any(k in blob for k in keys)
    except Exception:
        return False


def find_best_input_item(items):
    """
    Prefer real input classes; fallback to input-like clickable/focusable candidates.
    Returns the selected item or None.
    """
    best = None
    best_score = -10**9
    for it in items:
        try:
            cls = str(it[5] or "")
            simple_cls = _simple_class(cls)
            text = str(it[0] or "").lower()
            rid = str(it[4] or "").lower()
            desc = str(it[7] or "").lower()
            operatable = int(it[3])

            blob = " ".join([text, rid, desc, simple_cls.lower()])
            score = 0

            if _is_input_class(simple_cls):
                score += 1000
            if any(k in blob for k in ("search", "query", "input", "请输入", "搜索", "查询")):
                score += 300
            if operatable == 1:
                score += 60

            if score > best_score:
                best_score = score
                best = it
        except Exception:
            continue
    return best

def parseBounds(boundStr):
    boundPattern = '\\[-?(\\d+),-?(\\d+)\\]\\[-?(\\d+),-?(\\d+)\\]'
    result = re.match(boundPattern, boundStr)
    if result:
        left = int(result.group(1))
        top = int(result.group(2))
        right = int(result.group(3))
        bottom = int(result.group(4))
        return left, top, right, bottom

def parse_widgets(xmlRoot, in_list, in_drawer, testing):
    results = []
    attrib = xmlRoot.attrib

    visible = attrib.get('visible-to-user', 'true') == 'true'
    enabled = attrib.get('enabled', 'true') == 'true'
    if not visible or not enabled:
        return results

    text = str(attrib.get('text', '') or '').strip()
    the_class = attrib.get('class') or attrib.get('className', '')
    resource_id = attrib.get('resource-id', '')
    content_desc = attrib.get('content-desc', '')
    index = attrib.get('index', '')
    scrollable = attrib.get('scrollable', 'false')
    clickable = attrib.get('clickable', 'false')
    focusable = attrib.get('focusable', 'false')
    long_clickable = attrib.get('long-clickable', 'false')
    checkable = attrib.get('checkable', 'false')

    simple_cls = _simple_class(the_class)

    # --- text_class ---
    text_class = 0
    if simple_cls:
        if simple_cls == 'TextView':
            # clickable TextView behaves as button-like
            text_class = 20 if clickable == 'true' else 11
        else:
            text_class = convert_class_to_text_label(simple_cls)

    # list/drawer context fallback
    if text_class == 0 and (in_drawer or in_list):
        text_class = 25 if in_drawer else 24

    # --- bounds ---
    bounds = [0, 0, 0, 0]
    if 'bounds' in attrib:
        try:
            bound_str = attrib['bounds']
            if bound_str and len(bound_str) >= 10:
                left, top, right, bottom = parseBounds(bound_str)
                if left >= 0 and top >= 0 and right > left and bottom > top:
                    bounds = [left, top, right, bottom]
        except Exception as e:
            logger.debug(f"Bounds parse error: {e}")

    # --- operatable ---
    # Key fix: treat focusable/long-clickable/checkable as interactable,
    # and treat input widgets as interactable even if clickable=false.
    is_input = _is_input_class(simple_cls)
    is_interactable = (
        clickable == 'true'
        or scrollable == 'true'
        or focusable == 'true'
        or long_clickable == 'true'
        or checkable == 'true'
        or is_input
    )

    if scrollable == 'true':
        operatable = 2
    elif is_interactable:
        operatable = 1
    else:
        operatable = 0

    # keep rule:
    # - any operatable
    # - any input widget
    # - any TextView with text/desc (state info)
    # - any "input-like" hint node (helps clicking search containers)
    looks_input_like = False
    try:
        looks_input_like = is_input_like_item([
            text, text_class, bounds, operatable,
            resource_id, the_class, scrollable, content_desc, index
        ])
    except Exception:
        looks_input_like = False

    if operatable != 0 or is_input or looks_input_like or (simple_cls == 'TextView' and (text or content_desc)):
        results.append([
            text, text_class, bounds, operatable,
            resource_id, the_class, scrollable,
            content_desc, index
        ])

    # recurse
    if len(xmlRoot):
        for child in xmlRoot:
            new_in_list = in_list
            new_in_drawer = in_drawer
            if text_class == 12:
                new_in_list = True
            elif text_class == 7:
                new_in_drawer = True
            results.extend(parse_widgets(child, new_in_list, new_in_drawer, testing))

    return results
def generate_udid_str(activity_name,item_list):
    res = activity_name
    for i, item in enumerate(item_list):
        if i==2:
            continue
        res += str(item)
    return res